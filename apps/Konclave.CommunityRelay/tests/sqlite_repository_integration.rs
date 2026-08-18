use tempfile::tempdir;

#[path = "../src/persistence.rs"]
mod persistence;

use persistence::ServiceRecordRepository;

#[tokio::test]
async fn sqlite_repository_runs_migrations_and_commits_transactions() {
    let directory = tempdir().unwrap();
    let database_path = directory.path().join("service.db");
    let repository = ServiceRecordRepository::connect(&database_path)
        .await
        .unwrap();

    let first = repository.insert("alpha").await.unwrap();
    let second = repository.insert("beta").await.unwrap();

    assert_eq!(first, 1);
    assert_eq!(second, 2);

    let records = repository.list().await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].value, "alpha");
    assert_eq!(records[1].value, "beta");
}
