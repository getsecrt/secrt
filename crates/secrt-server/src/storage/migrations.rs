use std::collections::HashSet;

use deadpool_postgres::Pool;

use super::StorageError;

const MIGRATIONS: &[(&str, &str)] = &[(
    "001_initial.sql",
    include_str!("../../migrations/001_initial.sql"),
)];

pub async fn migrate(pool: &Pool) -> Result<Vec<String>, StorageError> {
    let mut client = pool.get().await?;

    client
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS migrations (\
                filename TEXT PRIMARY KEY,\
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()\
             )",
        )
        .await?;

    let rows = client.query("SELECT filename FROM migrations", &[]).await?;
    let applied: HashSet<String> = rows
        .iter()
        .filter_map(|r| r.try_get::<_, String>(0).ok())
        .collect();

    let mut newly_applied = Vec::new();
    for (filename, sql) in MIGRATIONS {
        if applied.contains(*filename) {
            continue;
        }

        let tx = client.build_transaction().start().await?;

        tx.batch_execute(sql).await?;
        tx.execute(
            "INSERT INTO migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING",
            &[filename],
        )
        .await?;

        tx.commit().await?;

        newly_applied.push((*filename).to_string());
    }

    Ok(newly_applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_sorted_and_non_empty() {
        assert!(!MIGRATIONS.is_empty());
        let names: Vec<&str> = MIGRATIONS.iter().map(|(n, _)| *n).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }
}
