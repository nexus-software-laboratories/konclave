use std::path::Path;

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Acquire, Sqlite, SqlitePool, Transaction};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct ServiceRecordRepository {
    pool: SqlitePool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub id: i64,
    pub value: String,
}

impl ServiceRecordRepository {
    pub async fn connect(database_path: &Path) -> anyhow::Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(database_path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    pub async fn insert(&self, value: &str) -> anyhow::Result<i64> {
        let mut transaction = self.pool.begin().await?;
        let id = insert_transaction(&mut transaction, value).await?;
        transaction.commit().await?;
        Ok(id)
    }

    pub async fn list(&self) -> anyhow::Result<Vec<ServiceRecord>> {
        let rows =
            sqlx::query_as::<_, (i64, String)>("SELECT id, value FROM service_records ORDER BY id")
                .fetch_all(&self.pool)
                .await?;

        Ok(rows
            .into_iter()
            .map(|(id, value)| ServiceRecord { id, value })
            .collect())
    }
}

pub async fn insert_transaction(
    transaction: &mut Transaction<'_, Sqlite>,
    value: &str,
) -> anyhow::Result<i64> {
    let connection = transaction.acquire().await?;
    let result = sqlx::query("INSERT INTO service_records (value) VALUES (?1)")
        .bind(value)
        .execute(&mut *connection)
        .await?;
    Ok(result.last_insert_rowid())
}
