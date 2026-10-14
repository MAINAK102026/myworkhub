-- MyWorkHub cloud schema. Run once in Supabase SQL Editor.
-- Do not put a service-role key in index.html or GitHub.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username = upper(username) and username ~ '^[A-Z0-9_]{3,24}$'),
  is_owner boolean not null default false,
  must_change_password boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.workspaces (
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique check (username = upper(username) and username ~ '^[A-Z0-9_]{3,24}$'),
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists workspaces_username_idx on public.workspaces(username);

create or replace function public.handle_new_myworkhub_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  normalized_username text;
  force_change boolean;
begin
  normalized_username := upper(coalesce(new.raw_user_meta_data ->> 'username', ''));
  force_change := coalesce((new.raw_user_meta_data ->> 'must_change_password')::boolean, false);
  if normalized_username !~ '^[A-Z0-9_]{3,24}$' then
    raise exception 'MyWorkHub username must be 3-24 letters, numbers, or underscores';
  end if;
  insert into public.profiles(id, username, must_change_password)
  values (new.id, normalized_username, force_change);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_myworkhub on auth.users;
create trigger on_auth_user_created_myworkhub
after insert on auth.users
for each row execute procedure public.handle_new_myworkhub_user();

create or replace function public.is_myworkhub_owner()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid()) and p.is_owner = true
  );
$$;

revoke all on function public.is_myworkhub_owner() from public;
grant execute on function public.is_myworkhub_owner() to authenticated;

alter table public.profiles enable row level security;
alter table public.workspaces enable row level security;

-- Users can read only their own profile. Owners can inspect profiles for administration.
drop policy if exists "profiles_select_self_or_owner" on public.profiles;
create policy "profiles_select_self_or_owner" on public.profiles
for select to authenticated
using (id = (select auth.uid()) or (select public.is_myworkhub_owner()));

-- Intentionally no client-side INSERT/UPDATE/DELETE policy for profiles.
-- Account profile creation is handled by the trusted auth trigger. Only service-role/admin
-- operations may change is_owner or must_change_password.

drop policy if exists "workspaces_select_self_or_owner" on public.workspaces;
create policy "workspaces_select_self_or_owner" on public.workspaces
for select to authenticated
using (user_id = (select auth.uid()) or (select public.is_myworkhub_owner()));

drop policy if exists "workspaces_insert_self" on public.workspaces;
create policy "workspaces_insert_self" on public.workspaces
for insert to authenticated
with check (user_id = (select auth.uid()) and username = (select p.username from public.profiles p where p.id = (select auth.uid())));

drop policy if exists "workspaces_update_self" on public.workspaces;
create policy "workspaces_update_self" on public.workspaces
for update to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()) and username = (select p.username from public.profiles p where p.id = (select auth.uid())));

grant select on public.profiles to authenticated;
grant select, insert, update on public.workspaces to authenticated;

-- IMPORTANT: after the first account is created, promote it manually in SQL Editor:
-- update public.profiles set is_owner = true where username = 'YOUR_OWNER_USERNAME';

-- A migrated account may clear its temporary-password flag only for itself.
create or replace function public.clear_myworkhub_password_change_flag()
returns void
language sql
security definer
set search_path = ''
as $$
  update public.profiles set must_change_password = false
  where id = (select auth.uid());
$$;
revoke all on function public.clear_myworkhub_password_change_flag() from public;
grant execute on function public.clear_myworkhub_password_change_flag() to authenticated;
