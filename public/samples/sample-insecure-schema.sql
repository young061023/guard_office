-- Guard Office DB security review sample. Do not use in production.
create table public.notes (
  id bigint generated always as identity primary key,
  owner_id uuid not null,
  title text not null,
  content text,
  created_at timestamptz default now()
);

-- Intentionally unsafe: grants every privilege to all database users.
grant all privileges on table public.notes to public;

-- Intentionally unsafe: function executes with its owner's privileges and does
-- not pin search_path.
create or replace function public.find_notes(query_text text)
returns setof public.notes
language plpgsql
security definer
as $$
begin
  return query execute 'select * from public.notes where title like ''%' || query_text || '%''';
end;
$$;
