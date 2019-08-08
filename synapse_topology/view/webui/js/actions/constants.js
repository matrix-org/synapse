export const DELEGATION_TYPES = {
  LOCAL: "local",
  WELL_KNOWN: "well_known",
  DNS: "dns",
}

export const REVERSE_PROXY_TYPES = {
  CADDY: "CADDY",
  APACHE: "APACHE",
  HAPROXY: "HAPROXY",
  NGINX: "NGINX",
  OTHER: "OTHER",
}

export const TLS_TYPES = {
  ACME: "ACME",
  TLS: "TLS",
  REVERSE_PROXY: "REVERSE_PROXY",
}

export const DATABASE_TYPES = {
  SQLITE3: "sqlite3",
  POSTGRES: "psycopg2",
}