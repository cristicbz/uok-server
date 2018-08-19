use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use errors::{Result, ResultExt};

pub type SqlitePool = Pool<SqliteConnectionManager>;

#[derive(Debug, Serialize)]
pub struct Event {
    pub username: String,
    pub event_type: String,
    pub raw_time: DateTime<FixedOffset>,
    pub time: i64,
}

pub struct EventStore {
    sqlite: SqlitePool,
}

impl EventStore {
    pub fn new(sqlite: SqlitePool) -> Result<Self> {
        sqlite
            .get()
            .map_err_internal()?
            .execute(
                "CREATE TABLE IF NOT EXISTS Events (
                    username           STRING NOT NULL,
                    time               INTEGER NOT NULL,
                    raw_time           STRING NOT NULL,
                    event_type         STRING NOT NULL,
                    PRIMARY KEY (username, time)
                )",
                &[],
            )
            .map_err_internal()?;

        Ok(EventStore { sqlite })
    }

    pub fn get_csv(
        &self,
        username: &str,
        min_time: Option<DateTime<FixedOffset>>,
        max_time: Option<DateTime<FixedOffset>>,
    ) -> Result<String> {
        let min_time = min_time.map(|time| time.timestamp()).unwrap_or(0);
        let max_time = max_time
            .map(|time| time.timestamp())
            .unwrap_or(i64::max_value());

        let mut csv = String::with_capacity(4096);
        let connection = self.sqlite.get().map_err_internal()?;
        let mut prepared = connection
            .prepare(
                "SELECT time, raw_time, event_type FROM Events
             WHERE username = ? AND (time BETWEEN ? AND ?)",
            )
            .map_err_internal()?;

        let mut rows = prepared
            .query(&[&username, &min_time, &max_time])
            .map_err_internal()?;
        while let Some(row) = rows.next() {
            let row = row.map_err_internal()?;
            let time: i64 = row.get(0);
            let raw_time: String = row.get(1);
            let event_type: String = row.get(2);
            let event_type = event_type.replace('"', r#""""#);

            csv.push_str(
                &DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(time, 0), Utc)
                    .to_rfc3339(),
            );
            csv.push(',');
            csv.push_str(&raw_time);
            csv.push(',');
            csv.push('"');
            csv.push_str(&event_type);
            csv.push('"');
            csv.push('\n');
        }

        Ok(csv)
    }

    pub fn put(&self, event: &Event) -> Result<()> {
        self.sqlite
            .get()
            .map_err_internal()?
            .execute(
                "INSERT OR REPLACE INTO Events (username, time, raw_time, event_type)
                 VALUES (?, ?, ?, ?)",
                &[
                    &event.username,
                    &event.raw_time.timestamp(),
                    &event.raw_time.to_rfc3339(),
                    &event.event_type,
                ],
            )
            .map_err_internal()?;
        info!("Added event {:?}.", event);
        Ok(())
    }
}
