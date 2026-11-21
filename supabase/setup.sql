-- =============================================================================
-- NOTES — Private Two-Person E2EE Messaging Backend Setup (Supabase PostgreSQL)
-- =============================================================================
-- Run this entire script in the Supabase SQL Editor (Database -> SQL Editor).
-- Prerequisite: Enable Anonymous Sign-Ins in Supabase Dashboard:
--   Authentication -> Providers -> Anonymous Sign-Ins -> Enable
-- =============================================================================

create extension if not exists pgcrypto;

-- 1. Tables
-- -----------------------------------------------------------------------------

create table if not exists public.rooms (
  id uuid primary key default gen_random_uuid(),
  invite_code text not null unique,
  invite_used boolean not null default false,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default timezone('utc', now())
);

create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  public_key text not null,
  joined_at timestamptz not null default timezone('utc', now()),
  primary key (room_id, user_id),
  constraint room_members_public_key_len check (char_length(public_key) between 32 and 128)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.rooms(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  body text not null,
  created_at timestamptz not null default timezone('utc', now()),
  constraint messages_body_not_empty check (char_length(body) between 1 and 16384)
);

create index if not exists idx_rooms_invite_code on public.rooms (invite_code);
create index if not exists idx_room_members_user_id on public.room_members (user_id);
create index if not exists idx_messages_room_created on public.messages (room_id, created_at asc);

-- 2. Database-Level Two-Participant Hard Invariant Trigger
-- -----------------------------------------------------------------------------
create or replace function public.enforce_max_two_room_members()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  member_count integer;
begin
  select count(*) into member_count
  from public.room_members
  where room_id = new.room_id;

  if member_count >= 2 then
    raise exception 'ROOM_FULL: A private room can never have more than two members.'
      using errcode = 'P0001';
  end if;

  return new;
end;
$$;

drop trigger if exists trg_enforce_max_two_room_members on public.room_members;
create trigger trg_enforce_max_two_room_members
  before insert on public.room_members
  for each row
  execute function public.enforce_max_two_room_members();

-- 3. Helper Membership Check (avoids recursive RLS lookups)
-- -----------------------------------------------------------------------------
create or replace function public.is_room_member(p_room_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.room_members
    where room_id = p_room_id
      and user_id = auth.uid()
  );
$$;

revoke all on function public.is_room_member(uuid) from public;
grant execute on function public.is_room_member(uuid) to authenticated;

-- 4. Row Level Security (RLS)
-- -----------------------------------------------------------------------------
alter table public.rooms enable row level security;
alter table public.room_members enable row level security;
alter table public.messages enable row level security;

-- Rooms: only members can read their own room metadata. Direct client inserts/updates are blocked.
drop policy if exists "rooms_select_member_only" on public.rooms;
create policy "rooms_select_member_only"
  on public.rooms
  for select
  to authenticated
  using (public.is_room_member(id));

-- Room members: members can read member rows (including peer public_key) for rooms they belong to.
drop policy if exists "room_members_select_same_room" on public.room_members;
create policy "room_members_select_same_room"
  on public.room_members
  for select
  to authenticated
  using (public.is_room_member(room_id));

-- Room members: users may delete only their own membership row (or via leave_private_room RPC).
drop policy if exists "room_members_delete_self" on public.room_members;
create policy "room_members_delete_self"
  on public.room_members
  for delete
  to authenticated
  using (auth.uid() = user_id);

-- Messages: only authenticated room members can read messages in their room.
drop policy if exists "messages_select_member_only" on public.messages;
create policy "messages_select_member_only"
  on public.messages
  for select
  to authenticated
  using (public.is_room_member(room_id));

-- Messages: only authenticated room members can insert messages as themselves.
drop policy if exists "messages_insert_member_only" on public.messages;
create policy "messages_insert_member_only"
  on public.messages
  for insert
  to authenticated
  with check (
    auth.uid() = author_id
    and public.is_room_member(room_id)
  );

-- 5. Unpredictable Invite Code Generator (~80 bits CSPRNG entropy)
-- -----------------------------------------------------------------------------
create or replace function public.generate_unpredictable_invite_code()
returns text
language plpgsql
volatile
security definer
set search_path = public
as $$
declare
  alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  raw_bytes bytea := gen_random_bytes(16);
  code text := '';
  i integer;
  idx integer;
begin
  -- 16 characters from 32-char unambiguous alphabet = 80 bits of entropy
  for i in 0..15 loop
    idx := (get_byte(raw_bytes, i) % 32) + 1;
    code := code || substr(alphabet, idx, 1);
    if i in (3, 7, 11) then
      code := code || '-';
    end if;
  end loop;
  return code;
end;
$$;

revoke all on function public.generate_unpredictable_invite_code() from public;

-- 6. Server-Side Room Management RPCs
-- -----------------------------------------------------------------------------

-- Create a new private room and register the creator as member #1 with their X25519 public key.
create or replace function public.create_private_room(p_public_key text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_room_id uuid;
  v_invite_code text;
  v_created_at timestamptz;
  v_attempts integer := 0;
begin
  if v_user_id is null then
    raise exception 'UNAUTHENTICATED: Anonymous authentication required.' using errcode = '28000';
  end if;

  if p_public_key is null or char_length(trim(p_public_key)) < 32 then
    raise exception 'INVALID_PUBLIC_KEY: Valid X25519 public key required.' using errcode = '22023';
  end if;

  loop
    v_attempts := v_attempts + 1;
    v_invite_code := public.generate_unpredictable_invite_code();

    begin
      insert into public.rooms (invite_code, created_by)
      values (v_invite_code, v_user_id)
      returning id, created_at into v_room_id, v_created_at;
      exit;
    exception when unique_violation then
      if v_attempts >= 5 then
        raise exception 'INVITE_GENERATION_FAILED: Please retry.' using errcode = 'P0001';
      end if;
    end;
  end loop;

  insert into public.room_members (room_id, user_id, public_key)
  values (v_room_id, v_user_id, trim(p_public_key));

  return jsonb_build_object(
    'room_id', v_room_id,
    'invite_code', v_invite_code,
    'invite_used', false,
    'created_at', v_created_at
  );
end;
$$;

-- Join an existing room using a single-use invitation code.
create or replace function public.join_private_room(p_invite_code text, p_public_key text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_normalized_code text;
  v_room record;
  v_member_count integer;
  v_already_member boolean;
  v_peer_public_key text;
  v_joined_at timestamptz;
begin
  if v_user_id is null then
    raise exception 'UNAUTHENTICATED: Anonymous authentication required.' using errcode = '28000';
  end if;

  if p_public_key is null or char_length(trim(p_public_key)) < 32 then
    raise exception 'INVALID_PUBLIC_KEY: Valid X25519 public key required.' using errcode = '22023';
  end if;

  v_normalized_code := upper(regexp_replace(coalesce(p_invite_code, ''), '[^A-Za-z0-9]', '', 'g'));
  if char_length(v_normalized_code) <> 16 then
    raise exception 'INVALID_CODE: Invitation code format is invalid.' using errcode = 'P0001';
  end if;

  v_normalized_code := substr(v_normalized_code, 1, 4) || '-' ||
                       substr(v_normalized_code, 5, 4) || '-' ||
                       substr(v_normalized_code, 9, 4) || '-' ||
                       substr(v_normalized_code, 13, 4);

  select * into v_room
  from public.rooms
  where invite_code = v_normalized_code
  for update;

  if not found then
    raise exception 'INVALID_CODE: No active room matches this invitation code.' using errcode = 'P0001';
  end if;

  select exists (
    select 1 from public.room_members
    where room_id = v_room.id and user_id = v_user_id
  ) into v_already_member;

  if v_already_member then
    -- Existing member restoring/re-entering via code: do not consume/error, return session state.
    select public_key into v_peer_public_key
    from public.room_members
    where room_id = v_room.id and user_id <> v_user_id
    limit 1;

    select joined_at into v_joined_at
    from public.room_members
    where room_id = v_room.id and user_id = v_user_id;

    return jsonb_build_object(
      'room_id', v_room.id,
      'invite_used', v_room.invite_used,
      'joined_at', v_joined_at,
      'peer_public_key', v_peer_public_key
    );
  end if;

  if v_room.invite_used then
    raise exception 'INVITE_ALREADY_USED: This invitation code has already been redeemed.' using errcode = 'P0001';
  end if;

  select count(*) into v_member_count
  from public.room_members
  where room_id = v_room.id;

  if v_member_count >= 2 then
    raise exception 'ROOM_FULL: This private room already has two participants.' using errcode = 'P0001';
  end if;

  insert into public.room_members (room_id, user_id, public_key)
  values (v_room.id, v_user_id, trim(p_public_key))
  returning joined_at into v_joined_at;

  update public.rooms
  set invite_used = true
  where id = v_room.id;

  select public_key into v_peer_public_key
  from public.room_members
  where room_id = v_room.id and user_id <> v_user_id
  limit 1;

  return jsonb_build_object(
    'room_id', v_room.id,
    'invite_used', true,
    'joined_at', v_joined_at,
    'peer_public_key', v_peer_public_key
  );
end;
$$;

-- Restore an existing session for an authenticated room member.
create or replace function public.restore_room_session(p_room_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_room record;
  v_member record;
  v_peer_public_key text;
  v_member_count integer;
begin
  if v_user_id is null then
    raise exception 'UNAUTHENTICATED: Anonymous authentication required.' using errcode = '28000';
  end if;

  select * into v_room
  from public.rooms
  where id = p_room_id;

  if not found then
    raise exception 'ROOM_NOT_FOUND: This room no longer exists.' using errcode = 'P0001';
  end if;

  select * into v_member
  from public.room_members
  where room_id = p_room_id and user_id = v_user_id;

  if not found then
    raise exception 'NOT_A_MEMBER: You are no longer a member of this room.' using errcode = 'P0001';
  end if;

  select public_key into v_peer_public_key
  from public.room_members
  where room_id = p_room_id and user_id <> v_user_id
  limit 1;

  select count(*) into v_member_count
  from public.room_members
  where room_id = p_room_id;

  return jsonb_build_object(
    'room_id', v_room.id,
    'invite_code', case when v_room.created_by = v_user_id and not v_room.invite_used then v_room.invite_code else null end,
    'invite_used', v_room.invite_used,
    'is_creator', (v_room.created_by = v_user_id),
    'joined_at', v_member.joined_at,
    'member_count', v_member_count,
    'peer_public_key', v_peer_public_key
  );
end;
$$;

-- Leave a private room; deletes the room and its messages once the last participant leaves.
create or replace function public.leave_private_room(p_room_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_remaining integer;
begin
  if v_user_id is null then
    raise exception 'UNAUTHENTICATED: Anonymous authentication required.' using errcode = '28000';
  end if;

  delete from public.room_members
  where room_id = p_room_id and user_id = v_user_id;

  select count(*) into v_remaining
  from public.room_members
  where room_id = p_room_id;

  if v_remaining = 0 then
    delete from public.rooms where id = p_room_id;
  end if;
end;
$$;

revoke all on function public.create_private_room(text) from public;
revoke all on function public.join_private_room(text, text) from public;
revoke all on function public.restore_room_session(uuid) from public;
revoke all on function public.leave_private_room(uuid) from public;

grant execute on function public.create_private_room(text) to authenticated;
grant execute on function public.join_private_room(text, text) to authenticated;
grant execute on function public.restore_room_session(uuid) to authenticated;
grant execute on function public.leave_private_room(uuid) to authenticated;

-- 7. Supabase Realtime Publication
-- -----------------------------------------------------------------------------
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;

  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'room_members'
  ) then
    alter publication supabase_realtime add table public.room_members;
  end if;
end;
$$;
