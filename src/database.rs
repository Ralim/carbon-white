use sqlx::{Sqlite, SqlitePool, migrate::MigrateDatabase};
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

/// Stores a new document unless its file is already on file.
///
/// Returns `Ok(Some(id))` when the row was inserted, or `Ok(None)` when a
/// document with the same `file_sha256` already exists. `ON CONFLICT DO NOTHING`
/// surfaces the clash as "nothing was written" rather than as an error, which
/// keeps this correct when two uploads of the same file race each other.
pub async fn insert_document_if_absent(
    pool: &SqlitePool,
    document: NewDocument,
) -> Result<Option<i64>, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO documents (
            title, part_number, manufacturer, document_id, document_version,
            package_marking, device_address, notes, storage_date,
            original_file_name, file_sha256, file_path, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(file_sha256) DO NOTHING
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

    if result.rows_affected() == 0 {
        return Ok(None);
    }

    Ok(Some(result.last_insert_rowid()))
}

/// Metadata fields that can be edited after a document is uploaded.
///
/// Bundling the optional fields keeps `update_document_metadata` from growing an
/// argument per column.
#[derive(Debug, Default, Clone)]
pub struct DocumentMetadataUpdate<'a> {
    pub title: &'a str,
    pub part_number: Option<&'a str>,
    pub manufacturer: Option<&'a str>,
    pub document_id: Option<&'a str>,
    pub document_version: Option<&'a str>,
    pub package_marking: Option<&'a str>,
    pub device_address: Option<&'a str>,
    pub notes: Option<&'a str>,
}

pub async fn update_document_metadata(
    pool: &SqlitePool,
    sha256: &str,
    update: &DocumentMetadataUpdate<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE documents
        SET title = ?,
            part_number = ?,
            manufacturer = ?,
            document_id = ?,
            document_version = ?,
            package_marking = ?,
            device_address = ?,
            notes = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE file_sha256 = ?
        "#,
    )
    .bind(update.title)
    .bind(update.part_number)
    .bind(update.manufacturer)
    .bind(update.document_id)
    .bind(update.document_version)
    .bind(update.package_marking)
    .bind(update.device_address)
    .bind(update.notes)
    .bind(sha256)
    .execute(pool)
    .await?;

    Ok(())
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

/// Rows returned per page by the paginated listings.
pub const PAGE_SIZE: i64 = 100;

/// A single page of documents plus the counts needed to render a pager.
#[derive(Debug)]
pub struct DocumentPage {
    pub documents: Vec<Document>,
    /// 1-based index of the page that was returned.
    pub page: i64,
    pub per_page: i64,
    /// Total number of documents matching the listing.
    pub total: i64,
    /// Row offset the query used. Always non-negative.
    pub offset: i64,
}

impl DocumentPage {
    /// Total number of pages, never less than 1 so the UI always has a page to show.
    ///
    /// `per_page` is a public field, so guard against zero rather than relying
    /// on the clamp inside [`get_documents_page`].
    pub fn total_pages(&self) -> i64 {
        if self.per_page <= 0 {
            return 1;
        }
        // `div_ceil` is still unstable for `i64`, so round up by hand.
        let raw = self.total / self.per_page;
        let has_remainder = self.total % self.per_page != 0;
        (raw + i64::from(has_remainder)).max(1)
    }

    /// True when this page is not the first one.
    pub fn has_previous(&self) -> bool {
        self.page > 1
    }

    /// True when at least one more document exists after this page.
    pub fn has_next(&self) -> bool {
        self.page < self.total_pages()
    }
}

/// Total number of documents, used to compute the pager bounds.
pub async fn count_documents(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM documents")
        .fetch_one(pool)
        .await
}

/// Returns one page of documents ordered newest-first.
///
/// `page` is 1-based and is clamped to a valid range, so an out-of-bounds or
/// hostile value yields the nearest page rather than an error.
pub async fn get_documents_page(
    pool: &SqlitePool,
    page: i64,
    per_page: i64,
) -> Result<DocumentPage, sqlx::Error> {
    let per_page = per_page.clamp(1, 1000);
    let total = count_documents(pool).await?;

    // An empty listing still reports one (empty) page rather than zero.
    let total_pages = {
        let raw = total / per_page;
        let has_remainder = total % per_page != 0;
        (raw + i64::from(has_remainder)).max(1)
    };
    // `clamp` keeps `page` within 1..=total_pages, so the subtraction below
    // cannot underflow even for i64::MIN.
    let page = page.clamp(1, total_pages);
    let offset = (page - 1) * per_page;

    let documents = sqlx::query_as::<_, Document>(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path
        FROM documents
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(DocumentPage {
        documents,
        page,
        per_page,
        total,
        offset,
    })
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
    use tempfile::{TempDir, tempdir};

    pub struct TestDb {
        pub pool: SqlitePool,
        _temp_dir: TempDir, // Only tracked for cleanup
    }

    async fn setup_test_db() -> TestDb {
        let temp_dir =
            tempdir().unwrap_or_else(|e| panic!("Failed to create temp dir for test {}", e));
        let data_dir = temp_dir.path().to_str().unwrap();
        let pool = init_db(data_dir).await.unwrap();

        TestDb {
            pool,
            _temp_dir: temp_dir,
        }
    }

    #[tokio::test]
    async fn test_database_initialization() {
        let test_db = setup_test_db().await;

        // Test that we can query the documents table
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
            .fetch_one(&test_db.pool)
            .await
            .unwrap();

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_and_search_document() {
        let test_db = setup_test_db().await;

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

        let id = insert_document_if_absent(&test_db.pool, new_doc)
            .await
            .unwrap()
            .expect("document should be inserted");
        assert!(id > 0);

        // Test search
        let results = search_documents(&test_db.pool, "Test").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Test Document");
        assert_eq!(results[0].part_number, Some("PN123".to_string()));
    }

    #[tokio::test]
    async fn test_get_document_by_sha256() {
        let test_db = setup_test_db().await;

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

        insert_document_if_absent(&test_db.pool, new_doc)
            .await
            .unwrap()
            .expect("document should be inserted");

        let result = get_document_by_sha256(&test_db.pool, "unique_sha256_hash")
            .await
            .unwrap();
        assert!(result.is_some());
        let doc = result.unwrap();
        assert_eq!(doc.title, "SHA Test Document");
        assert_eq!(doc.file_sha256, "unique_sha256_hash");
    }

    #[tokio::test]
    async fn test_insert_document_if_absent_rejects_duplicate() {
        let test_db = setup_test_db().await;

        let first = NewDocument {
            title: "Original Title".to_string(),
            part_number: Some("PN-ORIGINAL".to_string()),
            manufacturer: Some("Original Corp".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: Some("original notes".to_string()),
            storage_date: "2024-01-01".to_string(),
            original_file_name: "original.pdf".to_string(),
            file_sha256: "duplicate_hash".to_string(),
            file_path: "/tmp/test/duplicate_hash/original.pdf".to_string(),
        };

        let first_id = insert_document_if_absent(&test_db.pool, first)
            .await
            .unwrap()
            .expect("first insert should succeed");

        // Same content, different metadata and filename.
        let second = NewDocument {
            title: "Replacement Title".to_string(),
            part_number: Some("PN-REPLACEMENT".to_string()),
            manufacturer: Some("Replacement Corp".to_string()),
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: Some("replacement notes".to_string()),
            storage_date: "2025-12-31".to_string(),
            original_file_name: "replacement.pdf".to_string(),
            file_sha256: "duplicate_hash".to_string(),
            file_path: "/tmp/test/duplicate_hash/replacement.pdf".to_string(),
        };

        // Rejected rather than replacing the existing row.
        let result = insert_document_if_absent(&test_db.pool, second)
            .await
            .unwrap();
        assert!(result.is_none(), "duplicate content must be rejected");

        // The original row is untouched: no metadata, id, or path was replaced.
        let stored = get_document_by_sha256(&test_db.pool, "duplicate_hash")
            .await
            .unwrap()
            .expect("original document must still exist");

        assert_eq!(stored.id, first_id);
        assert_eq!(stored.title, "Original Title");
        assert_eq!(stored.part_number, Some("PN-ORIGINAL".to_string()));
        assert_eq!(stored.manufacturer, Some("Original Corp".to_string()));
        assert_eq!(stored.notes, Some("original notes".to_string()));
        assert_eq!(stored.original_file_name, "original.pdf");
        assert_eq!(stored.file_path, "/tmp/test/duplicate_hash/original.pdf");
        assert_eq!(stored.storage_date, "2024-01-01");

        // Exactly one row exists for that hash.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents WHERE file_sha256 = ?")
            .bind("duplicate_hash")
            .fetch_one(&test_db.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_insert_document_if_absent_allows_distinct_content() {
        let test_db = setup_test_db().await;

        // Different content means a different hash, so both must be accepted
        // even when the metadata is otherwise identical.
        for hash in ["hash_one", "hash_two", "hash_three"] {
            let inserted = insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: "Same Title".to_string(),
                    part_number: Some("PN-SAME".to_string()),
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "same.pdf".to_string(),
                    file_sha256: hash.to_string(),
                    file_path: format!("/tmp/test/{}/same.pdf", hash),
                },
            )
            .await
            .unwrap();

            assert!(
                inserted.is_some(),
                "distinct content ({hash}) must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn test_document_exists_by_sha256() {
        let test_db = setup_test_db().await;

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

        assert!(
            !document_exists_by_sha256(&test_db.pool, "exists_test_hash")
                .await
                .unwrap()
        );

        insert_document_if_absent(&test_db.pool, new_doc)
            .await
            .unwrap()
            .expect("document should be inserted");

        assert!(
            document_exists_by_sha256(&test_db.pool, "exists_test_hash")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_document_stats() {
        let test_db = setup_test_db().await;

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

        insert_document_if_absent(&test_db.pool, doc1)
            .await
            .unwrap()
            .expect("document should be inserted");
        insert_document_if_absent(&test_db.pool, doc2)
            .await
            .unwrap()
            .expect("document should be inserted");

        let stats = get_document_stats(&test_db.pool).await.unwrap();
        assert_eq!(stats.total_documents, 2);
        assert_eq!(stats.unique_manufacturers, 2);
    }

    #[tokio::test]
    async fn test_document_page_pagination() {
        let test_db = setup_test_db().await;

        // Seed 25 documents with distinct titles.
        for i in 0..25 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {:02}", i),
                    part_number: Some(format!("PN{:02}", i)),
                    manufacturer: Some("Test Corp".to_string()),
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: format!("doc{}.pdf", i),
                    file_sha256: format!("hash_{:02}", i),
                    file_path: format!("/tmp/test/{}/doc.pdf", i),
                },
            )
            .await
            .unwrap();
        }

        // Page 1 of 10 should hold the 10 newest, newest-first.
        let first = get_documents_page(&test_db.pool, 1, 10).await.unwrap();
        assert_eq!(first.page, 1);
        assert_eq!(first.per_page, 10);
        assert_eq!(first.total, 25);
        assert_eq!(first.total_pages(), 3);
        assert_eq!(first.documents.len(), 10);
        assert_eq!(first.documents[0].title, "Doc 24");
        assert_eq!(first.documents[9].title, "Doc 15");
        assert!(!first.has_previous());
        assert!(first.has_next());

        // Middle page.
        let second = get_documents_page(&test_db.pool, 2, 10).await.unwrap();
        assert_eq!(second.documents.len(), 10);
        assert_eq!(second.documents[0].title, "Doc 14");
        assert!(second.has_previous());
        assert!(second.has_next());

        // Final, partial page.
        let third = get_documents_page(&test_db.pool, 3, 10).await.unwrap();
        assert_eq!(third.documents.len(), 5);
        assert_eq!(third.documents[0].title, "Doc 04");
        assert!(third.has_previous());
        assert!(!third.has_next());

        // Pages must not overlap and together must cover every document.
        let mut seen: Vec<String> = Vec::new();
        for page in 1..=3 {
            let p = get_documents_page(&test_db.pool, page, 10).await.unwrap();
            seen.extend(p.documents.into_iter().map(|d| d.title));
        }
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), 25);
    }

    #[tokio::test]
    async fn test_document_page_clamps_out_of_range_values() {
        let test_db = setup_test_db().await;

        for i in 0..3 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {}", i),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: format!("doc{}.pdf", i),
                    file_sha256: format!("hash_{}", i),
                    file_path: "/tmp/test/doc.pdf".to_string(),
                },
            )
            .await
            .unwrap()
            .expect("document should be inserted");
        }

        // A page far past the end clamps to the last page rather than erroring.
        let beyond = get_documents_page(&test_db.pool, 9_999, 10).await.unwrap();
        assert_eq!(beyond.page, 1, "only one page exists, so it clamps to 1");
        assert_eq!(beyond.documents.len(), 3);

        // Non-positive page and page size are clamped rather than rejected.
        let zero_page = get_documents_page(&test_db.pool, 0, 10).await.unwrap();
        assert_eq!(zero_page.page, 1);

        let clamped_size = get_documents_page(&test_db.pool, 1, 0).await.unwrap();
        assert_eq!(
            clamped_size.per_page, 1,
            "page size is clamped to at least 1"
        );
        assert_eq!(clamped_size.documents.len(), 1);

        let huge = get_documents_page(&test_db.pool, 1, 1_000_000)
            .await
            .unwrap();
        assert_eq!(huge.per_page, 1000, "page size is capped to a sane maximum");
    }

    #[tokio::test]
    async fn test_document_page_empty_database() {
        let test_db = setup_test_db().await;

        let page = get_documents_page(&test_db.pool, 1, 100).await.unwrap();

        assert!(page.documents.is_empty());
        assert_eq!(page.total, 0);
        // Always at least one page so the UI has something to render.
        assert_eq!(page.total_pages(), 1);
        assert!(!page.has_previous());
        assert!(!page.has_next());
    }

    #[tokio::test]
    async fn test_default_page_size_is_100() {
        assert_eq!(PAGE_SIZE, 100);
    }

    #[tokio::test]
    async fn test_count_documents() {
        let test_db = setup_test_db().await;

        assert_eq!(count_documents(&test_db.pool).await.unwrap(), 0);

        for i in 0..3 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {}", i),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "doc.pdf".to_string(),
                    file_sha256: format!("hash_{}", i),
                    file_path: "/tmp/test/doc.pdf".to_string(),
                },
            )
            .await
            .unwrap()
            .expect("document should be inserted");
        }

        assert_eq!(count_documents(&test_db.pool).await.unwrap(), 3);
    }

    #[test]
    fn test_document_page_total_pages_guards_against_zero_per_page() {
        // `per_page` is a public field, so `total_pages` must not divide by zero
        // even though `get_documents_page` always clamps it to at least 1.
        let page = DocumentPage {
            documents: Vec::new(),
            page: 1,
            per_page: 0,
            total: 42,
            offset: 0,
        };
        assert_eq!(page.total_pages(), 1);

        let negative = DocumentPage {
            documents: Vec::new(),
            page: 1,
            per_page: -10,
            total: 42,
            offset: 0,
        };
        assert_eq!(negative.total_pages(), 1);
    }

    #[tokio::test]
    async fn test_document_page_clamps_extreme_page_values() {
        let test_db = setup_test_db().await;

        for i in 0..3 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {}", i),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "doc.pdf".to_string(),
                    file_sha256: format!("hash_{}", i),
                    file_path: "/tmp/test/doc.pdf".to_string(),
                },
            )
            .await
            .unwrap()
            .expect("document should be inserted");
        }

        // `i64::MIN` would underflow `page - 1` without the clamp; with only
        // 3 documents there is a single page, so both extremes land on 1.
        for hostile in [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX] {
            let page = get_documents_page(&test_db.pool, hostile, 10)
                .await
                .unwrap_or_else(|e| panic!("page={hostile} should not error: {e}"));

            assert_eq!(page.page, 1, "page={hostile} must clamp to 1");
            assert_eq!(page.documents.len(), 3);
            // A clamped page of 1 yields offset 0, so the full set comes back
            // rather than an empty tail from a huge negative offset.
            assert!(page.offset >= 0);
        }

        // On a multi-page listing the extremes clamp to the two ends.
        for i in 3..25 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {}", i),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "doc.pdf".to_string(),
                    file_sha256: format!("hash_{}", i),
                    file_path: "/tmp/test/doc.pdf".to_string(),
                },
            )
            .await
            .unwrap()
            .expect("document should be inserted");
        }

        // 25 docs at 10 per page => 3 pages.
        let first = get_documents_page(&test_db.pool, i64::MIN, 10)
            .await
            .unwrap();
        assert_eq!(first.page, 1, "i64::MIN must clamp to the first page");

        let last = get_documents_page(&test_db.pool, i64::MAX, 10)
            .await
            .unwrap();
        assert_eq!(last.page, 3, "i64::MAX must clamp to the last page");
    }

    #[tokio::test]
    async fn test_get_all_documents() {
        let test_db = setup_test_db().await;

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
        insert_document_if_absent(&test_db.pool, doc1)
            .await
            .unwrap()
            .expect("document should be inserted");
        insert_document_if_absent(&test_db.pool, doc2)
            .await
            .unwrap()
            .expect("document should be inserted");
        insert_document_if_absent(&test_db.pool, doc3)
            .await
            .unwrap()
            .expect("document should be inserted");

        // Get latest 2 documents
        let latest = get_latest_documents(&test_db.pool, 2).await.unwrap();
        assert_eq!(latest.len(), 2);

        // Should be ordered by ID descending (most recent first)
        assert_eq!(latest[0].title, "Third Document");
        assert_eq!(latest[1].title, "Second Document");

        // Test with limit larger than available documents
        let all_latest = get_latest_documents(&test_db.pool, 10).await.unwrap();
        assert_eq!(all_latest.len(), 3);
        assert_eq!(all_latest[0].title, "Third Document");
        assert_eq!(all_latest[1].title, "Second Document");
        assert_eq!(all_latest[2].title, "First Document");

        // Test with limit of 0
        let none = get_latest_documents(&test_db.pool, 0).await.unwrap();
        assert_eq!(none.len(), 0);
    }

    #[tokio::test]
    async fn test_update_document_metadata() {
        let test_db = setup_test_db().await;

        // Insert a document first
        let new_doc = NewDocument {
            title: "Original Title".to_string(),
            part_number: Some("PN001".to_string()),
            manufacturer: Some("Original Mfg".to_string()),
            document_id: Some("DOC001".to_string()),
            document_version: Some("1.0".to_string()),
            package_marking: Some("QFN32".to_string()),
            device_address: Some("0x48".to_string()),
            notes: Some("Original notes".to_string()),
            storage_date: "2024-01-01".to_string(),
            original_file_name: "test.pdf".to_string(),
            file_sha256: "update_test_hash".to_string(),
            file_path: "/tmp/test/update_test_hash.pdf".to_string(),
        };

        insert_document_if_absent(&test_db.pool, new_doc)
            .await
            .unwrap()
            .expect("document should be inserted");

        // Update the document metadata
        update_document_metadata(
            &test_db.pool,
            "update_test_hash",
            &DocumentMetadataUpdate {
                title: "Updated Title",
                part_number: Some("PN002"),
                manufacturer: Some("Updated Mfg"),
                document_id: Some("DOC002"),
                document_version: Some("2.0"),
                package_marking: Some("BGA64"),
                device_address: Some("0x49"),
                notes: Some("Updated notes"),
            },
        )
        .await
        .unwrap();

        // Verify the update
        let updated_doc = get_document_by_sha256(&test_db.pool, "update_test_hash")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated_doc.title, "Updated Title");
        assert_eq!(updated_doc.part_number, Some("PN002".to_string()));
        assert_eq!(updated_doc.manufacturer, Some("Updated Mfg".to_string()));
        assert_eq!(updated_doc.document_id, Some("DOC002".to_string()));
        assert_eq!(updated_doc.document_version, Some("2.0".to_string()));
        assert_eq!(updated_doc.package_marking, Some("BGA64".to_string()));
        assert_eq!(updated_doc.device_address, Some("0x49".to_string()));
        assert_eq!(updated_doc.notes, Some("Updated notes".to_string()));

        // File-related fields should remain unchanged
        assert_eq!(updated_doc.file_sha256, "update_test_hash");
        assert_eq!(updated_doc.original_file_name, "test.pdf");
        assert_eq!(updated_doc.storage_date, "2024-01-01");

        // Test updating with None values
        update_document_metadata(
            &test_db.pool,
            "update_test_hash",
            &DocumentMetadataUpdate {
                title: "Title Only",
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let updated_doc2 = get_document_by_sha256(&test_db.pool, "update_test_hash")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(updated_doc2.title, "Title Only");
        assert_eq!(updated_doc2.part_number, None);
        assert_eq!(updated_doc2.manufacturer, None);
        assert_eq!(updated_doc2.document_id, None);
        assert_eq!(updated_doc2.document_version, None);
        assert_eq!(updated_doc2.package_marking, None);
        assert_eq!(updated_doc2.device_address, None);
        assert_eq!(updated_doc2.notes, None);
    }
}
