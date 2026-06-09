//! The protected resource: a `documents` table and its CRUD operations.
//!
//! This uses its own sqlx pool, separate from the pool the casbin adapter owns. Runtime
//! queries (`sqlx::query`) keep the example free of compile-time `DATABASE_URL` requirements.

use anyhow::Result;
use sqlx::{PgPool, Row, postgres::PgPoolOptions};

use crate::domain::Document;

/// Open a connection pool to Postgres.
pub async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(5).connect(url).await?)
}

/// Create the `documents` table if needed, then reset it so every demo run is deterministic
/// (the first document created during the run is always `id = 1`).
pub async fn init_schema(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS documents (
            id          BIGSERIAL PRIMARY KEY,
            title       TEXT NOT NULL,
            content     TEXT NOT NULL,
            created_by  TEXT NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("TRUNCATE documents RESTART IDENTITY")
        .execute(pool)
        .await?;
    Ok(())
}

/// Insert a document and return its new id.
pub async fn create(pool: &PgPool, actor: &str, title: &str, content: &str) -> Result<i64> {
    let row = sqlx::query(
        "INSERT INTO documents (title, content, created_by) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(title)
    .bind(content)
    .bind(actor)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>("id"))
}

/// Fetch a document by id, if it exists.
pub async fn read(pool: &PgPool, id: i64) -> Result<Option<Document>> {
    let row = sqlx::query("SELECT id, title, content, created_by FROM documents WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| Document {
        id: r.get("id"),
        title: r.get("title"),
        content: r.get("content"),
        created_by: r.get("created_by"),
    }))
}

/// Update a document's content; returns the number of rows affected.
pub async fn update(pool: &PgPool, id: i64, content: &str) -> Result<u64> {
    let res = sqlx::query("UPDATE documents SET content = $1 WHERE id = $2")
        .bind(content)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

/// Delete a document; returns the number of rows affected.
pub async fn delete(pool: &PgPool, id: i64) -> Result<u64> {
    let res = sqlx::query("DELETE FROM documents WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}
