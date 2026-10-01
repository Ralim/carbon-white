use sqlx::{FromRow, Row, Sqlite, SqlitePool, migrate::MigrateDatabase, sqlite::SqlitePoolOptions};
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

    // The pool is configured with `after_connect` because these settings are
    // per-connection.
    let pool = SqlitePoolOptions::new()
        // SQLite serialises writers regardless of pool size, so a large pool
        // mostly adds lock contention on the upload path. A small pool keeps
        // the write lock predictable while WAL still allows concurrent reads.
        .max_connections(5)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // NORMAL is the recommended durability level under WAL: it
                // fsyncs at checkpoints rather than on every commit.
                sqlx::query("PRAGMA synchronous = NORMAL;")
                    .execute(&mut *conn)
                    .await?;
                // Wait for a lock held by another connection instead of
                // failing immediately with SQLITE_BUSY.
                sqlx::query("PRAGMA busy_timeout = 5000;")
                    .execute(&mut *conn)
                    .await?;
                // Set the page cache to 40 MiB (negative means the size is in
                // KiB rather than pages).
                sqlx::query("PRAGMA cache_size = -40960;")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(&db_url)
        .await?;

    // Unlike the settings above, the journal mode is a persistent property
    // recorded in the database file header. WAL lets readers run while a write is in flight and
    // removes the reader-blocks-writer stalls of the rollback journal.
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode = WAL;")
        .fetch_one(&pool)
        .await?;

    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(sqlx::Error::Configuration(
            format!("failed to enable WAL journaling, got `{journal_mode}`").into(),
        ));
    }

    // Run migrations. Order matters: each step is guarded by `user_version` and
    // advances it, so a step that ran first would cause a later step to believe
    // it had already been applied. The FTS backfill must therefore run before
    // the column drop, which is the step that records the higher version.
    create_tables(&pool).await?;
    create_fts_index(&pool).await?;
    drop_unused_columns(&pool).await?;

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
            file_path TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    // The per-column indexes on title, part_number, and manufacturer predate the
    // FTS5 index and no longer back any query. Search is answered from
    // documents_fts, pagination orders by the `id` primary key, and lookups go
    // through the UNIQUE index on file_sha256. Maintaining three more B-trees on
    // every insert and metadata edit is pure write overhead, so they are dropped
    // rather than recreated.
    sqlx::query(
        r#"
        DROP INDEX IF EXISTS idx_documents_title;
        DROP INDEX IF EXISTS idx_documents_part_number;
        DROP INDEX IF EXISTS idx_documents_manufacturer;
        "#,
    )
    .execute(pool)
    .await?;

    info!("Database tables created/verified successfully");
    Ok(())
}

/// `user_version` value recorded once the full-text index has been populated.
///
/// SQLite has no migration framework, so the schema's own `user_version` header
/// is used as the marker. Anything below this still needs a backfill.
const FTS_SCHEMA_VERSION: i64 = 1;

/// `user_version` value recorded once the unused audit columns have been dropped.
///
/// At this version the `documents` table holds exactly the columns the
/// [`Document`] struct reads, and no longer carries `created_at` or
/// `updated_at`.
const UNUSED_COLUMNS_SCHEMA_VERSION: i64 = 2;

/// Reads the schema version recorded in the database header.
async fn schema_version(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(pool)
        .await
}

/// Records the schema version once a migration step has succeeded.
async fn set_schema_version(pool: &SqlitePool, version: i64) -> Result<(), sqlx::Error> {
    // `PRAGMA user_version` does not accept a bound parameter, so the value is
    // interpolated. It is always a compile-time constant, never user input;
    // `AssertSqlSafe` records that for sqlx's injection check.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "PRAGMA user_version = {version};"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// True when `documents` has a column with the given name.
async fn column_exists(pool: &SqlitePool, column: &str) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query("PRAGMA table_info(documents)")
        .fetch_all(pool)
        .await?;

    Ok(rows.iter().any(|row| {
        row.try_get::<String, _>("name")
            .is_ok_and(|name| name == column)
    }))
}

/// Drops `created_at` and `updated_at` from databases that still carry them.
///
/// Neither column is read anywhere in the application. `created_at` was only
/// used by two query helpers that had no callers, and `updated_at` was written
/// on insert and edit but never read back. Both are removed so the table matches
/// the [`Document`] struct exactly and stops paying to store them.
///
/// The version guard keeps this to databases created before the change; a
/// freshly created table never has these columns in the first place. Each
/// `DROP COLUMN` is additionally checked against `PRAGMA table_info` so a
/// partially migrated database converges instead of erroring.
async fn drop_unused_columns(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    if schema_version(pool).await? >= UNUSED_COLUMNS_SCHEMA_VERSION {
        return Ok(());
    }

    for column in ["created_at", "updated_at"] {
        if column_exists(pool, column).await? {
            // Safe here: neither column is a key, is indexed, or is named in the
            // FTS maintenance triggers, all of which SQLite requires before a
            // column may be dropped.
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "ALTER TABLE documents DROP COLUMN {column};"
            )))
            .execute(pool)
            .await?;
            info!("Dropped unused column documents.{column}");
        }
    }

    set_schema_version(pool, UNUSED_COLUMNS_SCHEMA_VERSION).await?;
    Ok(())
}

/// Creates the FTS5 index over `documents` and keeps it in sync via triggers.
async fn create_fts_index(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
            title, part_number, manufacturer, document_id,
            package_marking, device_address, notes, original_file_name,
            content='documents',
            content_rowid='id',
            tokenize='unicode61'
        );
        "#,
    )
    .execute(pool)
    .await?;

    // With an external content table the index is not populated by INSERTs into
    // `documents` itself, so triggers maintain it. The delete side of a change
    // must restate the *old* column values, because that is what the index
    // currently holds.
    sqlx::query(
        r#"
        CREATE TRIGGER IF NOT EXISTS documents_fts_ai AFTER INSERT ON documents BEGIN
            INSERT INTO documents_fts(
                rowid, title, part_number, manufacturer, document_id,
                package_marking, device_address, notes, original_file_name
            ) VALUES (
                new.id, new.title, new.part_number, new.manufacturer, new.document_id,
                new.package_marking, new.device_address, new.notes, new.original_file_name
            );
        END;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TRIGGER IF NOT EXISTS documents_fts_ad AFTER DELETE ON documents BEGIN
            INSERT INTO documents_fts(
                documents_fts, rowid, title, part_number, manufacturer,
                document_id, package_marking, device_address, notes, original_file_name
            ) VALUES (
                'delete', old.id, old.title, old.part_number, old.manufacturer,
                old.document_id, old.package_marking, old.device_address,
                old.notes, old.original_file_name
            );
        END;
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TRIGGER IF NOT EXISTS documents_fts_au AFTER UPDATE ON documents BEGIN
            INSERT INTO documents_fts(
                documents_fts, rowid, title, part_number, manufacturer,
                document_id, package_marking, device_address, notes, original_file_name
            ) VALUES (
                'delete', old.id, old.title, old.part_number, old.manufacturer,
                old.document_id, old.package_marking, old.device_address,
                old.notes, old.original_file_name
            );
            INSERT INTO documents_fts(
                rowid, title, part_number, manufacturer, document_id,
                package_marking, device_address, notes, original_file_name
            ) VALUES (
                new.id, new.title, new.part_number, new.manufacturer, new.document_id,
                new.package_marking, new.device_address, new.notes, new.original_file_name
            );
        END;
        "#,
    )
    .execute(pool)
    .await?;

    // Backfill for databases that predate the index. `rebuild` regenerates the
    // whole index from the content table, which is what an existing deployment
    // needs; it is guarded so it runs once rather than on every startup.
    if schema_version(pool).await? < FTS_SCHEMA_VERSION {
        sqlx::query("INSERT INTO documents_fts(documents_fts) VALUES('rebuild');")
            .execute(pool)
            .await?;
        set_schema_version(pool, FTS_SCHEMA_VERSION).await?;
        info!("Populated full-text search index from existing documents");
    }

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
/// document with the same `file_sha256` already exists.
pub async fn insert_document_if_absent(
    pool: &SqlitePool,
    document: NewDocument,
) -> Result<Option<i64>, sqlx::Error> {
    let result = sqlx::query(
        r#"
        INSERT INTO documents (
            title, part_number, manufacturer, document_id, document_version,
            package_marking, device_address, notes, storage_date,
            original_file_name, file_sha256, file_path
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            notes = ?
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

/// Builds a safe FTS5 `MATCH` expression from a raw user query.
///
/// Each term is wrapped in double quotes, which FTS5 reads as a literal string.
/// That matters for correctness, not just tidiness: FTS5 has its own query
/// language, so an unquoted term containing `*`, `-`, `:`, `NEAR`, or a bare
/// quote would either be interpreted as query syntax -- silently changing which
/// documents match -- or raise a syntax error and fail the whole request. The
/// previous `LIKE '%term%'` had the same class of problem, where a bare `%`
/// matched every row.
///
/// Embedded quotes are doubled, which is how FTS5 escapes them inside a string.
/// Terms are combined with `AND` so that a multi-word query narrows rather than
/// widens, and the last term is matched as a prefix so results update as the
/// user types.
///
/// Returns `None` when the input holds no searchable term, which the caller
/// should treat as "no results" rather than as a match-everything query.
fn build_fts_query(raw: &str) -> Option<String> {
    // A term made only of punctuation tokenises to nothing. Passing such a term
    // to FTS5 -- especially with a `*` suffix -- is a syntax error, so those are
    // dropped before quoting.
    let terms: Vec<&str> = raw
        .split_whitespace()
        .filter(|term| term.chars().any(char::is_alphanumeric))
        .collect();

    let (last, rest) = terms.split_last()?;

    let mut parts: Vec<String> = rest
        .iter()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect();
    parts.push(format!("\"{}\"*", last.replace('"', "\"\"")));

    Some(parts.join(" AND "))
}

/// Full-text search across document metadata.
pub async fn search_documents(
    pool: &SqlitePool,
    query: &str,
) -> Result<Vec<Document>, sqlx::Error> {
    let Some(match_expression) = build_fts_query(query) else {
        // Nothing searchable in the input. Returning an empty set keeps this
        // consistent with a query that simply matches no documents.
        return Ok(Vec::new());
    };

    let documents = sqlx::query_as::<_, Document>(
        r#"
        SELECT documents.id, documents.title, documents.part_number,
               documents.manufacturer, documents.document_id,
               documents.document_version, documents.package_marking,
               documents.device_address, documents.notes, documents.storage_date,
               documents.original_file_name, documents.file_sha256, documents.file_path
        FROM documents_fts
        JOIN documents ON documents.id = documents_fts.rowid
        WHERE documents_fts MATCH ?
        ORDER BY bm25(documents_fts, 10.0, 8.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0),
                 documents.title ASC
        LIMIT 100
        "#,
    )
    .bind(match_expression)
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
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM documents WHERE file_sha256 = ?)")
            .bind(sha256)
            .fetch_one(pool)
            .await?;

    Ok(exists)
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

    // `page` is caller supplied, so bound it before it is used to build an
    // offset: `(page - 1) * per_page` would overflow for values near i64::MAX.
    // This is a wide sanity bound, not the real one; the real bounds come from
    // the total row count below.
    let page = page.clamp(1, i64::MAX / per_page);

    // The rows and the total come from a single statement. `COUNT(*) OVER ()`
    // is evaluated over the whole result set before LIMIT applies, so it
    // reports the true total without a second COUNT(*) round trip.
    let (documents, total) = fetch_page_with_total(pool, page, per_page).await?;
    if let Some(total) = total {
        return Ok(DocumentPage {
            documents,
            page,
            per_page,
            total,
            offset: (page - 1) * per_page,
        });
    }

    // An empty result means the requested page is past the end of the table, so
    // the window function had no row to report the total on. Fall back to an
    // explicit count to find the real bounds, then re-read the clamped page.
    // This costs a second query, but only for out-of-range requests.
    let total = count_documents(pool).await?;
    let total_pages = {
        let raw = total / per_page;
        let has_remainder = total % per_page != 0;
        (raw + i64::from(has_remainder)).max(1)
    };
    // `clamp` keeps `page` within 1..=total_pages, so the subtraction below
    // cannot underflow even for i64::MIN.
    let page = page.clamp(1, total_pages);
    let (documents, _) = fetch_page_with_total(pool, page, per_page).await?;

    Ok(DocumentPage {
        documents,
        page,
        per_page,
        total,
        offset: (page - 1) * per_page,
    })
}

/// Fetches one page of documents newest-first together with the total number of
/// documents in the table.
///
/// The total is `None` when the page came back empty: the window function has no
/// row to carry it, so there is nothing to read.
async fn fetch_page_with_total(
    pool: &SqlitePool,
    page: i64,
    per_page: i64,
) -> Result<(Vec<Document>, Option<i64>), sqlx::Error> {
    let offset = (page - 1) * per_page;

    // Selected as a plain row rather than via `query_as` because the extra
    // `total_count` column has to be read by name alongside the document.
    // `Document::from_row` ignores columns it does not know about.
    let rows = sqlx::query(
        r#"
        SELECT id, title, part_number, manufacturer, document_id, document_version,
               package_marking, device_address, notes, storage_date,
               original_file_name, file_sha256, file_path,
               COUNT(*) OVER () AS total_count
        FROM documents
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        "#,
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    let total = rows
        .first()
        .map(|row| row.try_get::<i64, _>("total_count"))
        .transpose()?;

    let documents = rows
        .iter()
        .map(Document::from_row)
        .collect::<Result<Vec<Document>, sqlx::Error>>()?;

    Ok((documents, total))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    pub struct TestDb {
        pub pool: SqlitePool,
        _temp_dir: TempDir, // Only tracked for cleanup
    }

    /// Builds a document row for tests, leaving every optional field unset.
    fn doc(title: &str, sha: &str) -> NewDocument {
        NewDocument {
            title: title.to_string(),
            part_number: None,
            manufacturer: None,
            document_id: None,
            document_version: None,
            package_marking: None,
            device_address: None,
            notes: None,
            storage_date: "2024-01-01".to_string(),
            original_file_name: "file.pdf".to_string(),
            file_sha256: sha.to_string(),
            file_path: format!("/tmp/test/{sha}/file.pdf"),
        }
    }

    async fn insert(pool: &SqlitePool, document: NewDocument) -> i64 {
        insert_document_if_absent(pool, document)
            .await
            .unwrap()
            .expect("document should insert")
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
    async fn test_page_total_is_counted_before_limit() {
        let test_db = setup_test_db().await;

        for i in 0..25 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Doc {i:02}"),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "d.pdf".to_string(),
                    file_sha256: format!("page-total-{i:02}"),
                    file_path: format!("/tmp/test/page-total-{i:02}/d.pdf"),
                },
            )
            .await
            .unwrap();
        }

        // The total now rides along on the paged query via COUNT(*) OVER ().
        // If it were ever evaluated after LIMIT it would report the page size
        // rather than the table size, so check a middle page and a short final
        // page as well as the first.
        for (page, expected_rows) in [(1, 10), (2, 10), (3, 5)] {
            let result = get_documents_page(&test_db.pool, page, 10).await.unwrap();
            assert_eq!(
                result.total, 25,
                "page {page} must report the full table size"
            );
            assert_eq!(
                result.documents.len(),
                expected_rows,
                "page {page} row count"
            );
            assert_eq!(result.total_pages(), 3);
        }
    }

    #[tokio::test]
    async fn test_document_exists_distinguishes_present_and_absent() {
        let test_db = setup_test_db().await;

        assert!(
            !document_exists_by_sha256(&test_db.pool, "nothing-here")
                .await
                .unwrap()
        );

        insert_document_if_absent(
            &test_db.pool,
            NewDocument {
                title: "Present".to_string(),
                part_number: None,
                manufacturer: None,
                document_id: None,
                document_version: None,
                package_marking: None,
                device_address: None,
                notes: None,
                storage_date: "2024-01-01".to_string(),
                original_file_name: "p.pdf".to_string(),
                file_sha256: "present-sha".to_string(),
                file_path: "/tmp/test/present-sha/p.pdf".to_string(),
            },
        )
        .await
        .unwrap();

        assert!(
            document_exists_by_sha256(&test_db.pool, "present-sha")
                .await
                .unwrap()
        );
        assert!(
            !document_exists_by_sha256(&test_db.pool, "absent-sha")
                .await
                .unwrap()
        );

        // The empty string is a legitimate argument and must simply not match,
        // rather than being treated as a wildcard or erroring.
        assert!(!document_exists_by_sha256(&test_db.pool, "").await.unwrap());
    }

    #[test]
    fn test_build_fts_query_quotes_terms_and_prefixes_the_last() {
        assert_eq!(
            build_fts_query("datasheet").as_deref(),
            Some("\"datasheet\"*")
        );
        assert_eq!(
            build_fts_query("acme 5550").as_deref(),
            Some("\"acme\" AND \"5550\"*")
        );
    }

    #[test]
    fn test_build_fts_query_neutralises_fts_syntax() {
        // Every one of these would change the meaning of the query, or fail it
        // outright, if the input were passed through unquoted.
        assert_eq!(build_fts_query("a*b").as_deref(), Some("\"a*b\"*"));
        assert_eq!(
            build_fts_query("title:secret").as_deref(),
            Some("\"title:secret\"*")
        );
        assert_eq!(build_fts_query("NEAR").as_deref(), Some("\"NEAR\"*"));
        assert_eq!(build_fts_query("a-b").as_deref(), Some("\"a-b\"*"));
        // Embedded quotes are doubled, which is FTS5's own escape rule.
        assert_eq!(build_fts_query("a\"b").as_deref(), Some("\"a\"\"b\"*"));
    }

    #[test]
    fn test_build_fts_query_rejects_input_with_no_searchable_term() {
        // Under the old `LIKE '%term%'` a bare `%` matched every row. These
        // inputs have no alphanumeric content, so they yield no query at all
        // rather than a match-everything one.
        assert_eq!(build_fts_query(""), None);
        assert_eq!(build_fts_query("   "), None);
        assert_eq!(build_fts_query("%"), None);
        assert_eq!(build_fts_query("_"), None);
        assert_eq!(build_fts_query("%% __"), None);
        assert_eq!(build_fts_query("\"\"\""), None);
    }

    #[tokio::test]
    async fn test_search_finds_documents_across_fields() {
        let test_db = setup_test_db().await;

        let mut acme = doc("5550 Datasheet", "sha-acme");
        acme.manufacturer = Some("Acme Corp".to_string());
        insert(&test_db.pool, acme).await;

        let mut other = doc("Unrelated", "sha-other");
        other.notes = Some("mentions globex in passing".to_string());
        insert(&test_db.pool, other).await;

        let by_title = search_documents(&test_db.pool, "5550").await.unwrap();
        assert_eq!(by_title.len(), 1);
        assert_eq!(by_title[0].title, "5550 Datasheet");

        // Only the first document mentions Acme anywhere, so this exercises the
        // manufacturer column specifically.
        let by_manufacturer = search_documents(&test_db.pool, "Acme").await.unwrap();
        assert_eq!(by_manufacturer.len(), 1);
        assert_eq!(by_manufacturer[0].title, "5550 Datasheet");

        let by_notes = search_documents(&test_db.pool, "passing").await.unwrap();
        assert_eq!(by_notes.len(), 1);
        assert_eq!(by_notes[0].title, "Unrelated");
    }

    #[tokio::test]
    async fn test_search_multi_word_narrows_results() {
        let test_db = setup_test_db().await;

        let mut both = doc("Acme 5550 datasheet", "sha-both");
        both.manufacturer = Some("Acme".to_string());
        insert(&test_db.pool, both).await;

        let mut only_one = doc("Globex 1234 datasheet", "sha-globex");
        only_one.manufacturer = Some("Globex".to_string());
        insert(&test_db.pool, only_one).await;

        // Terms are combined with AND, so requiring both narrows rather than
        // widens the result set.
        let results = search_documents(&test_db.pool, "acme datasheet")
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Acme 5550 datasheet");
    }

    #[tokio::test]
    async fn test_search_wildcards_do_not_match_everything() {
        let test_db = setup_test_db().await;

        for i in 0..5 {
            insert(
                &test_db.pool,
                doc(&format!("Document {i}"), &format!("sha-{i}")),
            )
            .await;
        }

        // A bare `%` used to be interpolated straight into `LIKE '%term%'`,
        // matching every row. It now carries no searchable term.
        assert!(
            search_documents(&test_db.pool, "%")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            search_documents(&test_db.pool, "_")
                .await
                .unwrap()
                .is_empty()
        );
        // Punctuation mixed into a real term stays literal rather than acting
        // as a wildcard, and must not error.
        assert!(
            search_documents(&test_db.pool, "a%b")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            search_documents(&test_db.pool, "\"")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            search_documents(&test_db.pool, "a\"b")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_search_ranks_title_matches_first() {
        let test_db = setup_test_db().await;

        // The term appears in a title, in a manufacturer, and only in notes.
        // The bm25 weights are ordered so title wins.
        let mut title_hit = doc("Widget Manual", "sha-title");
        title_hit.manufacturer = Some("Elsewhere".to_string());
        insert(&test_db.pool, title_hit).await;

        let mut mfr_hit = doc("Something Else Entirely", "sha-mfr");
        mfr_hit.manufacturer = Some("Widget Ltd".to_string());
        insert(&test_db.pool, mfr_hit).await;

        let mut note_hit = doc("Unrelated Title", "sha-note");
        note_hit.notes = Some("widget referenced here".to_string());
        insert(&test_db.pool, note_hit).await;

        let results = search_documents(&test_db.pool, "widget").await.unwrap();
        let titles: Vec<&str> = results.iter().map(|d| d.title.as_str()).collect();

        assert_eq!(titles.len(), 3, "all three should match: {titles:?}");
        assert_eq!(titles[0], "Widget Manual", "title match should rank first");
    }

    #[tokio::test]
    async fn test_fts_index_tracks_updates_and_deletes() {
        let test_db = setup_test_db().await;
        insert(&test_db.pool, doc("Original Heading", "sha-mutable")).await;

        assert_eq!(
            search_documents(&test_db.pool, "original")
                .await
                .unwrap()
                .len(),
            1
        );

        // The update trigger has to drop the stale tokens as well as add new
        // ones, or the document matches both values forever.
        update_document_metadata(
            &test_db.pool,
            "sha-mutable",
            &DocumentMetadataUpdate {
                title: "Replacement Heading",
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(
            search_documents(&test_db.pool, "original")
                .await
                .unwrap()
                .is_empty(),
            "the old title should no longer match"
        );
        assert_eq!(
            search_documents(&test_db.pool, "replacement")
                .await
                .unwrap()
                .len(),
            1
        );

        // And the delete trigger has to remove the row from the index.
        let id = get_document_by_sha256(&test_db.pool, "sha-mutable")
            .await
            .unwrap()
            .expect("document should still exist")
            .id;
        assert!(delete_document_by_id(&test_db.pool, id).await.unwrap());
        assert!(
            search_documents(&test_db.pool, "replacement")
                .await
                .unwrap()
                .is_empty(),
            "a deleted document should not still match"
        );
    }

    #[tokio::test]
    async fn test_fts_index_is_backfilled_for_existing_documents() {
        let test_db = setup_test_db().await;
        insert(&test_db.pool, doc("Pre-existing Datasheet", "sha-legacy")).await;

        // Simulate a database written before the index existed: the index is
        // empty and the version marker has not been advanced.
        sqlx::query("DELETE FROM documents_fts;")
            .execute(&test_db.pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA user_version = 0;")
            .execute(&test_db.pool)
            .await
            .unwrap();

        assert!(
            search_documents(&test_db.pool, "pre-existing")
                .await
                .unwrap()
                .is_empty(),
            "index should be empty before the migration runs"
        );

        create_fts_index(&test_db.pool).await.unwrap();

        assert_eq!(
            search_documents(&test_db.pool, "pre-existing")
                .await
                .unwrap()
                .len(),
            1,
            "the migration should have backfilled the existing document"
        );
    }

    #[tokio::test]
    async fn test_fts_backfill_runs_only_once() {
        let test_db = setup_test_db().await;
        insert(&test_db.pool, doc("Backfill Guard", "sha-guard")).await;

        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&test_db.pool)
            .await
            .unwrap();
        // init_db runs every migration step, so the recorded version is the
        // last one's. The FTS backfill is guarded by the lower of the two.
        assert_eq!(version, UNUSED_COLUMNS_SCHEMA_VERSION);
        // The column drop must record a higher version than the FTS step, since
        // it runs second and its guard would otherwise skip the backfill.
        const { assert!(UNUSED_COLUMNS_SCHEMA_VERSION > FTS_SCHEMA_VERSION) };

        // Re-running the migration on a populated index must not duplicate or
        // discard anything, which is what the version guard prevents.
        create_fts_index(&test_db.pool).await.unwrap();
        create_fts_index(&test_db.pool).await.unwrap();

        assert_eq!(
            search_documents(&test_db.pool, "backfill")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(count_documents(&test_db.pool).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_search_matches_token_prefixes_not_substrings() {
        let test_db = setup_test_db().await;

        let mut doc = doc("Datasheet 5550", "sha-5550");
        doc.part_number = Some("PN-9000".to_string());
        insert(&test_db.pool, doc).await;

        // Terms match at the start of a token, so a partial part number still
        // finds the document.
        assert_eq!(
            search_documents(&test_db.pool, "555").await.unwrap().len(),
            1,
            "a token prefix should match"
        );

        // A fragment from the middle of a token does not. The old
        // `LIKE '%term%'` matched those too, so this is a deliberate change:
        // FTS5 tokenises on word boundaries rather than scanning substrings.
        assert!(
            search_documents(&test_db.pool, "550")
                .await
                .unwrap()
                .is_empty(),
            "a mid-token fragment should not match"
        );
    }

    #[tokio::test]
    async fn test_search_query_plan_uses_the_fts_index() {
        let test_db = setup_test_db().await;

        let expression = build_fts_query("datasheet").unwrap();
        let rows = sqlx::query(
            "EXPLAIN QUERY PLAN \
             SELECT documents.id FROM documents_fts \
             JOIN documents ON documents.id = documents_fts.rowid \
             WHERE documents_fts MATCH ? \
             ORDER BY bm25(documents_fts, 10.0, 8.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0)",
        )
        .bind(expression)
        .fetch_all(&test_db.pool)
        .await
        .unwrap();

        let plan: String = rows
            .iter()
            .map(|row| sqlx::Row::try_get::<String, _>(row, "detail").unwrap())
            .collect::<Vec<_>>()
            .join(" | ");

        assert!(
            plan.contains("VIRTUAL TABLE INDEX"),
            "search should be driven by the FTS index, got plan: {plan}"
        );
    }

    #[tokio::test]
    async fn test_unused_columns_are_absent_from_schema() {
        let test_db = setup_test_db().await;

        assert!(
            !column_exists(&test_db.pool, "created_at").await.unwrap(),
            "created_at should not be present on a current database"
        );
        assert!(
            !column_exists(&test_db.pool, "updated_at").await.unwrap(),
            "updated_at should not be present on a current database"
        );

        // The table should hold exactly the columns `Document` reads, so the
        // schema and the struct cannot drift apart unnoticed.
        let expected = [
            "id",
            "title",
            "part_number",
            "manufacturer",
            "document_id",
            "document_version",
            "package_marking",
            "device_address",
            "notes",
            "storage_date",
            "original_file_name",
            "file_sha256",
            "file_path",
        ];
        let rows = sqlx::query("PRAGMA table_info(documents)")
            .fetch_all(&test_db.pool)
            .await
            .unwrap();
        let actual: Vec<String> = rows
            .iter()
            .map(|row| sqlx::Row::try_get::<String, _>(row, "name").unwrap())
            .collect();

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn test_migration_drops_columns_from_a_legacy_database() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();

        // Build a database in the shape earlier versions produced: the two audit
        // columns present, the unused indexes present, and no migration marker.
        let url = format!("sqlite:{}/carbon.db", data_dir);
        Sqlite::create_database(&url).await.unwrap();
        let legacy = SqlitePool::connect(&url).await.unwrap();
        sqlx::query(
            r#"
            CREATE TABLE documents (
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
            );
            CREATE INDEX idx_documents_title ON documents(title);
            CREATE INDEX idx_documents_part_number ON documents(part_number);
            CREATE INDEX idx_documents_manufacturer ON documents(manufacturer);
            "#,
        )
        .execute(&legacy)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO documents (title, storage_date, original_file_name, file_sha256, file_path)
             VALUES ('Legacy Doc', '2024-01-01', 'legacy.pdf', 'legacy-sha', '/tmp/legacy.pdf')",
        )
        .execute(&legacy)
        .await
        .unwrap();
        assert!(column_exists(&legacy, "created_at").await.unwrap());
        legacy.close().await;

        // Opening it through the normal path must migrate it in place without
        // losing the existing row.
        let pool = init_db(data_dir).await.unwrap();

        assert!(!column_exists(&pool, "created_at").await.unwrap());
        assert!(!column_exists(&pool, "updated_at").await.unwrap());

        let remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_documents_title','idx_documents_part_number','idx_documents_manufacturer')")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, 0, "unused indexes should be dropped");

        // The pre-existing document survived and is still searchable through the
        // freshly built full-text index.
        assert_eq!(count_documents(&pool).await.unwrap(), 1);
        let found = search_documents(&pool, "legacy").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].title, "Legacy Doc");
    }

    #[tokio::test]
    async fn test_migration_is_idempotent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();

        // init_db runs every migration; running the steps again on the result
        // must be a no-op rather than an error.
        let first = init_db(data_dir).await.unwrap();
        let version = schema_version(&first).await.unwrap();
        assert_eq!(version, UNUSED_COLUMNS_SCHEMA_VERSION);
        first.close().await;

        let second = init_db(data_dir).await.unwrap();
        assert_eq!(schema_version(&second).await.unwrap(), version);
        assert!(!column_exists(&second, "created_at").await.unwrap());
        drop_unused_columns(&second).await.unwrap();
        assert!(!column_exists(&second, "created_at").await.unwrap());
    }

    #[tokio::test]
    async fn test_fts_backfill_runs_before_column_drop() {
        // The column drop records the higher schema version, so running it
        // first would mark the database as current and make the FTS backfill
        // skip a database that has never been indexed. This pins the ordering.
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap();

        let url = format!("sqlite:{}/carbon.db", data_dir);
        Sqlite::create_database(&url).await.unwrap();
        let pool = SqlitePool::connect(&url).await.unwrap();
        sqlx::query(
            "CREATE TABLE documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL, part_number TEXT, manufacturer TEXT,
                document_id TEXT, document_version TEXT, package_marking TEXT,
                device_address TEXT, notes TEXT, storage_date TEXT NOT NULL,
                original_file_name TEXT NOT NULL, file_sha256 TEXT NOT NULL UNIQUE,
                file_path TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO documents (title, storage_date, original_file_name, file_sha256, file_path)
             VALUES ('Ordering Probe', '2024-01-01', 'p.pdf', 'probe-sha', '/tmp/p.pdf')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let migrated = init_db(data_dir).await.unwrap();

        // The row must be findable, which is only true if the backfill ran and
        // was not skipped by the column drop having claimed the version first.
        assert_eq!(
            search_documents(&migrated, "ordering").await.unwrap().len(),
            1
        );
        assert!(!column_exists(&migrated, "created_at").await.unwrap());
    }

    #[tokio::test]
    async fn test_journal_mode_is_wal() {
        let test_db = setup_test_db().await;

        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&test_db.pool)
            .await
            .unwrap();

        assert_eq!(
            mode.to_lowercase(),
            "wal",
            "WAL lets readers run during a write instead of blocking it"
        );
    }

    #[tokio::test]
    async fn test_pragmas_apply_to_every_pooled_connection() {
        let test_db = setup_test_db().await;

        // The per-connection PRAGMAs used to be run once against the pool,
        // which reached only one arbitrary connection while the rest silently
        // kept the defaults. Hold two connections open and check both.
        let mut first = test_db.pool.acquire().await.unwrap();
        let mut second = test_db.pool.acquire().await.unwrap();

        for (label, conn) in [("first", &mut first), ("second", &mut second)] {
            let cache: i64 = sqlx::query_scalar("PRAGMA cache_size")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            assert_eq!(
                cache, -40960,
                "{label} connection should have the 40 MiB cache"
            );

            let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            assert_eq!(sync, 1, "{label} connection should use synchronous=NORMAL");

            let busy: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
                .fetch_one(&mut **conn)
                .await
                .unwrap();
            assert_eq!(busy, 5000, "{label} connection should wait on a busy lock");
        }
    }

    #[tokio::test]
    async fn test_writes_succeed_while_a_read_is_open() {
        let test_db = setup_test_db().await;

        // The point of WAL: a long-lived read cursor must not block a writer.
        // Under the default rollback journal this second insert would fail or
        // block until the reader finished.
        let mut reader = test_db.pool.acquire().await.unwrap();
        sqlx::query("BEGIN").execute(&mut *reader).await.unwrap();
        sqlx::query("SELECT COUNT(*) FROM documents")
            .fetch_one(&mut *reader)
            .await
            .unwrap();

        for i in 0..3 {
            insert_document_if_absent(
                &test_db.pool,
                NewDocument {
                    title: format!("Concurrent {i}"),
                    part_number: None,
                    manufacturer: None,
                    document_id: None,
                    document_version: None,
                    package_marking: None,
                    device_address: None,
                    notes: None,
                    storage_date: "2024-01-01".to_string(),
                    original_file_name: "c.pdf".to_string(),
                    file_sha256: format!("concurrent-{i}"),
                    file_path: format!("/tmp/test/concurrent-{i}/c.pdf"),
                },
            )
            .await
            .unwrap();
        }

        sqlx::query("COMMIT").execute(&mut *reader).await.unwrap();

        assert_eq!(count_documents(&test_db.pool).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn test_no_redundant_sha256_index() {
        let test_db = setup_test_db().await;

        // The implicit index behind the UNIQUE constraint is reported with a
        // NULL `sql`, so matching on the SQL text finds only explicitly created
        // indexes -- which is exactly the duplicate we want gone.
        let redundant: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'index' AND tbl_name = 'documents' \
             AND sql LIKE '%file_sha256%'",
        )
        .fetch_one(&test_db.pool)
        .await
        .unwrap();

        assert_eq!(
            redundant, 0,
            "file_sha256 is already UNIQUE, so no explicit index should exist"
        );
    }

    #[tokio::test]
    async fn test_sha256_lookup_still_uses_an_index() {
        let test_db = setup_test_db().await;

        insert_document_if_absent(
            &test_db.pool,
            NewDocument {
                title: "Indexed Document".to_string(),
                part_number: None,
                manufacturer: None,
                document_id: None,
                document_version: None,
                package_marking: None,
                device_address: None,
                notes: None,
                storage_date: "2024-01-01".to_string(),
                original_file_name: "test.pdf".to_string(),
                file_sha256: "feedface".to_string(),
                file_path: "/tmp/test/feedface/test.pdf".to_string(),
            },
        )
        .await
        .unwrap();

        // Dropping the explicit index must not degrade the hot dedup/lookup
        // path: the UNIQUE index has to still satisfy it.
        // `EXPLAIN QUERY PLAN` yields (id, parent, notused, detail); the plan
        // text lives in the `detail` column, so read it by name.
        let rows = sqlx::query(
            "EXPLAIN QUERY PLAN SELECT id FROM documents WHERE file_sha256 = 'feedface'",
        )
        .fetch_all(&test_db.pool)
        .await
        .unwrap();
        let plan: String = sqlx::Row::try_get(&rows[0], "detail").unwrap();

        assert!(
            plan.contains("USING INDEX") || plan.contains("USING COVERING INDEX"),
            "sha256 lookup should use an index, got plan: {plan}"
        );

        // And the lookup still returns the row.
        assert!(
            get_document_by_sha256(&test_db.pool, "feedface")
                .await
                .unwrap()
                .is_some()
        );
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
