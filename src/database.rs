use sqlx::{migrate::MigrateDatabase, Sqlite, SqlitePool};
use std::path::Path;
use tracing::info;

pub async fn init_db(data_dir: &str) -> Result<SqlitePool, sqlx::Error> {
    let db_path = Path::new(data_dir).join("carbon.db");
    let db_url = format!("sqlite:{}", db_path.display());

    // Create database if it doesn't exist
    if !Sqlite::database_exists(&db_url).await.unwrap_or(false) {
        info!("Creating database at {}", db_url);
        Sqlite::create_database(&db_url).await?;
    }

    let pool = SqlitePool::connect(&db_url).await?;

    // Set SQLite cache size to 40 MiB (40960 KiB, negative means size in KiB)
    sqlx::query("PRAGMA cache_size = -40960;")
        .execute(&pool)
        .await?;

    // Run migrations
    create_tables(&pool).await?;

    info!("Database initialized successfully");
    Ok(pool)
}

async fn create_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            part_number TEXT,
            manufacturer TEXT,
            document_id TEXT,
            document_version TEXT,
            package_marking TEXT,
            device_address TEXT,
            notes TEXT,
            storage_date TEXT NOT NULL,
            original_file_name TEXT NOT NULL,
            file_sha256 TEXT NOT NULL UNIQUE,
            file_path TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create index on commonly searched fields
    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_documents_title ON documents(title);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_documents_part_number ON documents(part_number);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_documents_manufacturer ON documents(manufacturer);
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_documents_sha256 ON documents(file_sha256);
        "#,
    )
    .execute(pool)
    .await?;

    info!("Database tables created/verified successfully");
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct Document {
    pub id: i64,
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
    pub file_path: String,
}

#[derive(Debug)]
pub struct NewDocument {
    pub title: String,
    pub part_number: Option<String>,
    pub manufacturer: Option<String>,
    pub document_id: Option<String>,
    pub document_version: Option<String>,
    pub package_marking: Option<String>,
    pub device_address: Option<String>,
    pub notes: Option<String>,
    pub storage_date: String,
    pub original_file_name: String,
    pub file_sha256: String,
    pub file_path: String,
}

pub async fn insert_or_update_document(
    pool: &SqlitePool,
    document: NewDocument,
) -> Result<i64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT OR REPLACE INTO documents (
            title, part_number, manufacturer, document_id, document_version,
            package_marking, device_address, notes, storage_date,
            original_file_name, file_sha256, file_path, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        "#,
    )
    .bind(&document.title)
    .bind(&document.part_number)
    .bind(&document.manufacturer)
    .bind(&document.document_id)
    .bind(&document.document_version)
    .bind(&document.package_marking)
    .bind(&document.device_address)
    .bind(&document.notes)
    .bind(&document.storage_date)
    .bind(&document.original_file_name)
    .bind(&document.file_sha256)
    .bind(&document.file_path)
    .execute(pool)
    .await?;

    Ok(result.last_insert_rowid())
}

pub async fn search_documents(
    pool: &SqlitePool,
    query: &str,
) -> Result<Vec<Document>, sqlx::Error> {
    let search_term = format!("%{}%", query);

    let documents = sqlx::query_as::<_, Document>(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path
        FROM documents
        WHERE title LIKE ?
           OR part_number LIKE ?
           OR manufacturer LIKE ?
           OR document_id LIKE ?
           OR package_marking LIKE ?
           OR device_address LIKE ?
           OR notes LIKE ?
           OR original_file_name LIKE ?
        ORDER BY
            CASE
                WHEN title LIKE ? THEN 1
                WHEN part_number LIKE ? THEN 2
                WHEN manufacturer LIKE ? THEN 3
                ELSE 4
            END,
            title ASC
        LIMIT 100
        "#,
    )
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .bind(&search_term)
    .fetch_all(pool)
    .await?;

    Ok(documents)
}

pub async fn get_document_by_sha256(
    pool: &SqlitePool,
    sha256: &str,
) -> Result<Option<Document>, sqlx::Error> {
    let document = sqlx::query_as::<_, Document>(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path
        FROM documents
        WHERE file_sha256 = ?
        "#,
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?;

    Ok(document)
}

pub async fn document_exists_by_sha256(
    pool: &SqlitePool,
    sha256: &str,
) -> Result<bool, sqlx::Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents WHERE file_sha256 = ?")
        .bind(sha256)
        .fetch_one(pool)
        .await?;

    Ok(count > 0)
}

pub async fn get_all_documents(pool: &SqlitePool) -> Result<Vec<Document>, sqlx::Error> {
    let documents = sqlx::query_as::<_, Document>(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path
        FROM documents
        ORDER BY created_at DESC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(documents)
}

pub async fn get_latest_documents(
    pool: &SqlitePool,
    limit: u32,
) -> Result<Vec<Document>, sqlx::Error> {
    let documents = sqlx::query_as::<_, Document>(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path
        FROM documents
        ORDER BY id DESC
        LIMIT ?
        "#,
    )
    .bind(limit as i64)
    .fetch_all(pool)
    .await?;

    Ok(documents)
}

pub async fn delete_document_by_id(pool: &SqlitePool, id: i64) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM documents WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

pub async fn get_document_stats(pool: &SqlitePool) -> Result<DocumentStats, sqlx::Error> {
    let total_documents: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
        .fetch_one(pool)
        .await?;

    let unique_manufacturers: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT manufacturer) FROM documents WHERE manufacturer IS NOT NULL AND manufacturer != ''",
    )
    .fetch_one(pool)
    .await?;

    let recent_uploads: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM documents WHERE created_at >= datetime('now', '-7 days')",
    )
    .fetch_one(pool)
    .await?;

    Ok(DocumentStats {
        total_documents,
        unique_manufacturers,
        recent_uploads,
    })
}

#[derive(Debug)]
pub struct DocumentStats {
    pub total_documents: i64,
    pub unique_manufacturers: i64,
    pub recent_uploads: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    async fn setup_test_db() -> SqlitePool {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();
        init_db(data_dir).await.unwrap()
    }

    #[tokio::test]
    async fn test_database_initialization() {
        let pool = setup_test_db().await;

        // Test that we can query the documents table
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_and_search_document() {
        let pool = setup_test_db().await;

        let new_doc = NewDocument {
            title: "Test Document".to_string(),
            part_number: Some("PN123".to_string()),
            manufacturer: Some("Test Corp".to_string()),
            document_id: Some("DOC001".to_string()),
            document_version: Some("1.0".to_string()),
            package_marking: Some("QFN32".to_string()),
            device_address: Some("0x48".to_string()),
            notes: Some("Test notes".to_string()),
            storage_date: "2024-01-01".to_string(),
            original_file_name: "test.pdf".to_string(),
            file_sha256: "abcd1234567890".to_string(),
            file_path: "/tmp/test/abcd1234567890/test.pdf".to_string(),
        };

        let id = insert_or_update_document(&pool, new_doc).await.unwrap();
        assert!(id > 0);

        // Test search
        let results = search_documents(&pool, "Test").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Test Document");
        assert_eq!(results[0].part_number, Some("PN123".to_string()));
    }

    #[tokio::test]
    async fn test_get_document_by_sha256() {
        let pool = setup_test_db().await;

        let new_doc = NewDocument {
            title: "SHA Test Document".to_string(),
            part_number: None,
            manufacturer: None,
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "sha_test.pdf".to_string(),
            file_sha256: "unique_sha256_hash".to_string(),
            file_path: "/tmp/test/unique_sha256_hash/sha_test.pdf".to_string(),
        };

        insert_or_update_document(&pool, new_doc).await.unwrap();

        let result = get_document_by_sha256(&pool, "unique_sha256_hash")
            .await
            .unwrap();
        assert!(result.is_some());
        let doc = result.unwrap();
        assert_eq!(doc.title, "SHA Test Document");
        assert_eq!(doc.file_sha256, "unique_sha256_hash");
    }

    #[tokio::test]
    async fn test_document_exists_by_sha256() {
        let pool = setup_test_db().await;

        let new_doc = NewDocument {
            title: "Exists Test".to_string(),
            part_number: None,
            manufacturer: None,
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "exists.pdf".to_string(),
            file_sha256: "exists_test_hash".to_string(),
            file_path: "/tmp/test/exists_test_hash/exists.pdf".to_string(),
        };

        assert!(!document_exists_by_sha256(&pool, "exists_test_hash")
            .await
            .unwrap());

        insert_or_update_document(&pool, new_doc).await.unwrap();

        assert!(document_exists_by_sha256(&pool, "exists_test_hash")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_get_document_stats() {
        let pool = setup_test_db().await;

        // Insert test documents
        let doc1 = NewDocument {
            title: "Doc 1".to_string(),
            part_number: None,
            manufacturer: Some("Manufacturer A".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "doc1.pdf".to_string(),
            file_sha256: "hash1".to_string(),
            file_path: "/tmp/test/hash1/doc1.pdf".to_string(),
        };

        let doc2 = NewDocument {
            title: "Doc 2".to_string(),
            part_number: None,
            manufacturer: Some("Manufacturer B".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "doc2.pdf".to_string(),
            file_sha256: "hash2".to_string(),
            file_path: "/tmp/test/hash2/doc2.pdf".to_string(),
        };

        insert_or_update_document(&pool, doc1).await.unwrap();
        insert_or_update_document(&pool, doc2).await.unwrap();

        let stats = get_document_stats(&pool).await.unwrap();
        assert_eq!(stats.total_documents, 2);
        assert_eq!(stats.unique_manufacturers, 2);
    }

    #[tokio::test]
    async fn test_get_latest_documents() {
        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();
        let pool = init_db(data_dir).await.unwrap();

        // Insert test documents with different timestamps
        let doc1 = NewDocument {
            title: "First Document".to_string(),
            part_number: Some("PN001".to_string()),
            manufacturer: Some("Manufacturer A".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "first.pdf".to_string(),
            file_sha256: "hash001".to_string(),
            file_path: "/tmp/test/hash001/first.pdf".to_string(),
        };

        let doc2 = NewDocument {
            title: "Second Document".to_string(),
            part_number: Some("PN002".to_string()),
            manufacturer: Some("Manufacturer B".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-02".to_string(),
            original_file_name: "second.pdf".to_string(),
            file_sha256: "hash002".to_string(),
            file_path: "/tmp/test/hash002/second.pdf".to_string(),
        };

        let doc3 = NewDocument {
            title: "Third Document".to_string(),
            part_number: Some("PN003".to_string()),
            manufacturer: Some("Manufacturer C".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-03".to_string(),
            original_file_name: "third.pdf".to_string(),
            file_sha256: "hash003".to_string(),
            file_path: "/tmp/test/hash003/third.pdf".to_string(),
        };

        // Insert documents in order
        insert_or_update_document(&pool, doc1).await.unwrap();
        insert_or_update_document(&pool, doc2).await.unwrap();
        insert_or_update_document(&pool, doc3).await.unwrap();

        // Get latest 2 documents
        let latest = get_latest_documents(&pool, 2).await.unwrap();
        assert_eq!(latest.len(), 2);

        // Should be ordered by ID descending (most recent first)
        assert_eq!(latest[0].title, "Third Document");
        assert_eq!(latest[1].title, "Second Document");

        // Test with limit larger than available documents
        let all_latest = get_latest_documents(&pool, 10).await.unwrap();
        assert_eq!(all_latest.len(), 3);
        assert_eq!(all_latest[0].title, "Third Document");
        assert_eq!(all_latest[1].title, "Second Document");
        assert_eq!(all_latest[2].title, "First Document");

        // Test with limit of 0
        let none = get_latest_documents(&pool, 0).await.unwrap();
        assert_eq!(none.len(), 0);
    }
}
