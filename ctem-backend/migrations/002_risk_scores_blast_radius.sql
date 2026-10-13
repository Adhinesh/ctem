alter table risk_scores
    add column if not exists blast_radius numeric not null default 1.0;

alter table risk_scores
    add column if not exists criticality_mismatch boolean not null default false;

alter table risk_scores
    add column if not exists priority_tier text check (priority_tier in ('P1', 'P2', 'P3', 'P4'));

alter table risk_scores
    add column if not exists sla_hours integer;
