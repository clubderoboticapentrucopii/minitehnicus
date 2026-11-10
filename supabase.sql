-- ============================================================
-- Minitehnicus Baia Sprie - schema bazei de date (Supabase)
-- Rulezi acest fisier O SINGURA DATA, in Supabase: SQL Editor -> New query -> Run.
-- IMPORTANT: inainte de rulare, inlocuieste EMAIL_ADMIN_AICI (jos, la sectiunea 7)
-- cu adresa de email cu care te vei inregistra ca administrator.
-- ============================================================

-- 1) TABELE ---------------------------------------------------

create table if not exists public.admins (
  email text primary key
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.children (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 120),
  birth_date date,
  kit text check (kit in ('Essential','Prime')),
  joined date not null default current_date,
  parent_email text,
  parent_email2 text,
  active boolean not null default true,
  notes text check (char_length(notes) <= 500),
  created_at timestamptz not null default now()
);

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  lesson_key text,
  title text check (char_length(title) <= 160),
  date date not null,
  time text check (char_length(time) <= 20),
  place text check (char_length(place) <= 160),
  note text check (char_length(note) <= 500),
  done boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.attendance (
  session_id uuid not null references public.sessions(id) on delete cascade,
  child_id uuid not null references public.children(id) on delete cascade,
  present boolean not null default false,
  bonus integer not null default 0 check (bonus between -1000 and 1000),
  primary key (session_id, child_id)
);

create table if not exists public.settings (
  key text primary key,
  value text not null
);

create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 2 and 160),
  description text check (char_length(description) <= 1000),
  date date not null,
  time text check (char_length(time) <= 20),
  place text check (char_length(place) <= 160),
  capacity integer check (capacity is null or capacity > 0),
  open boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.event_rsvps (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.events(id) on delete cascade,
  name text not null check (char_length(name) between 2 and 120),
  contact text not null check (char_length(contact) between 3 and 160),
  adults integer not null default 1 check (adults between 0 and 10),
  kids integer not null default 0 check (kids between 0 and 15),
  note text check (char_length(note) <= 500),
  consent boolean not null check (consent is true),
  created_at timestamptz not null default now(),
  check (adults + kids >= 1)
);

create index if not exists attendance_child_idx on public.attendance(child_id);
create index if not exists rsvps_event_idx on public.event_rsvps(event_id);

-- 2) FUNCTII AJUTATOARE ---------------------------------------

create or replace function public.jwt_email()
returns text language sql stable as $$
  select lower(coalesce(auth.jwt() ->> 'email', ''))
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admins a
    where lower(a.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  )
$$;

create or replace function public.is_parent_of(cid uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.children c
    where c.id = cid
      and public.jwt_email() <> ''
      and (lower(c.parent_email) = public.jwt_email()
           or lower(c.parent_email2) = public.jwt_email())
  )
$$;

-- Totaluri publice pe eveniment (fara nume sau contacte)
create or replace function public.event_counts()
returns table (event_id uuid, rsvps bigint, adults bigint, kids bigint)
language sql stable security definer set search_path = public as $$
  select r.event_id, count(*), coalesce(sum(r.adults), 0), coalesce(sum(r.kids), 0)
  from public.event_rsvps r
  group by r.event_id
$$;

grant execute on function public.is_admin() to anon, authenticated;
grant execute on function public.event_counts() to anon, authenticated;

-- 3) PROFILURI AUTOMATE LA INREGISTRARE ------------------------

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email)
  values (new.id, lower(new.email))
  on conflict (id) do update set email = excluded.email;
  return new;
end
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

insert into public.profiles (id, email)
select id, lower(email) from auth.users
on conflict (id) do nothing;

-- 4) LIMITA DE LOCURI LA EVENIMENTE ----------------------------

create or replace function public.check_event_capacity()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  ev public.events%rowtype;
  used integer;
begin
  select * into ev from public.events where id = new.event_id;
  if not found or ev.open is not true then
    raise exception 'Inscrierile pentru acest eveniment sunt inchise.';
  end if;
  if ev.capacity is not null then
    select coalesce(sum(adults + kids), 0) into used
    from public.event_rsvps where event_id = new.event_id;
    if used + new.adults + new.kids > ev.capacity then
      raise exception 'Nu mai sunt suficiente locuri la acest eveniment.';
    end if;
  end if;
  return new;
end
$$;

drop trigger if exists rsvp_capacity on public.event_rsvps;
create trigger rsvp_capacity
  before insert on public.event_rsvps
  for each row execute function public.check_event_capacity();

-- 5) REGULI DE ACCES (Row Level Security) ----------------------

alter table public.admins       enable row level security;
alter table public.profiles     enable row level security;
alter table public.children     enable row level security;
alter table public.sessions     enable row level security;
alter table public.attendance   enable row level security;
alter table public.settings     enable row level security;
alter table public.events       enable row level security;
alter table public.event_rsvps  enable row level security;

-- admins: vazuti doar de admin; se modifica doar din SQL Editor
drop policy if exists admins_select on public.admins;
create policy admins_select on public.admins for select using (public.is_admin());

-- profiles: admin vede toate, fiecare isi vede propriul profil
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select
  using (public.is_admin() or id = auth.uid());

-- children: admin gestioneaza tot; parintele vede doar copilul lui
drop policy if exists children_select on public.children;
create policy children_select on public.children for select
  using (
    public.is_admin()
    or (public.jwt_email() <> ''
        and (lower(parent_email) = public.jwt_email()
             or lower(parent_email2) = public.jwt_email()))
  );
drop policy if exists children_admin on public.children;
create policy children_admin on public.children for all
  using (public.is_admin()) with check (public.is_admin());

-- sessions: publice la citire, doar admin scrie
drop policy if exists sessions_select on public.sessions;
create policy sessions_select on public.sessions for select using (true);
drop policy if exists sessions_admin on public.sessions;
create policy sessions_admin on public.sessions for all
  using (public.is_admin()) with check (public.is_admin());

-- attendance: admin tot; parintele doar copilul lui
drop policy if exists attendance_select on public.attendance;
create policy attendance_select on public.attendance for select
  using (public.is_admin() or public.is_parent_of(child_id));
drop policy if exists attendance_admin on public.attendance;
create policy attendance_admin on public.attendance for all
  using (public.is_admin()) with check (public.is_admin());

-- settings: publice la citire, doar admin scrie
drop policy if exists settings_select on public.settings;
create policy settings_select on public.settings for select using (true);
drop policy if exists settings_admin on public.settings;
create policy settings_admin on public.settings for all
  using (public.is_admin()) with check (public.is_admin());

-- events: publice la citire, doar admin scrie
drop policy if exists events_select on public.events;
create policy events_select on public.events for select using (true);
drop policy if exists events_admin on public.events;
create policy events_admin on public.events for all
  using (public.is_admin()) with check (public.is_admin());

-- event_rsvps: oricine poate adauga o inscriere; doar admin vede/sterge
drop policy if exists rsvps_insert on public.event_rsvps;
create policy rsvps_insert on public.event_rsvps for insert
  to anon, authenticated with check (consent is true);
drop policy if exists rsvps_admin on public.event_rsvps;
create policy rsvps_admin on public.event_rsvps for all
  using (public.is_admin()) with check (public.is_admin());

-- 6) SETARI IMPLICITE -------------------------------------------

insert into public.settings (key, value)
values ('points_per_session', '10')
on conflict (key) do nothing;

-- 7) ADMINISTRATOR -----------------------------------------------
-- Inlocuieste cu emailul tau real, intre ghilimele, INAINTE de a rula.
insert into public.admins (email)
values (lower('EMAIL_ADMIN_AICI'))
on conflict do nothing;
