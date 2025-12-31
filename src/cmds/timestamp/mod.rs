//! @alias: ts
//! @about: Print or parse timestamps

use anyhow::Result;
use clap::Parser;
use tracing::warn;

use chrono::prelude::*;

use crate::CmdExecute;

#[derive(Parser)]
#[command(name = "time")]
pub struct Cmd {
    #[arg(short = 'f', help = "Print format")]
    format: Option<String>,

    #[arg(help = "Any timestamp or datetime")]
    time: Option<Vec<String>>,
}

static LAYOUTS: [&str; 4] = ["%s", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"];

fn _execute(t: String, fmt: Option<String>) -> Result<String, ()> {
    for l in LAYOUTS {
        let dt: NaiveDateTime = match NaiveDateTime::parse_from_str(t.as_str(), l) {
            Ok(dt) => dt,
            Err(_) => match NaiveDate::parse_from_str(t.as_str(), l) {
                Ok(dt) => dt.and_hms_opt(0, 0, 0).unwrap(),
                Err(_) => {
                    warn!("Invalid timestamp or datetime: {}", t);
                    continue;
                }
            },
        };

        let r = match fmt.clone() {
            Some(f) => format!("{}", dt.format(f.as_str())),
            None => {
                if l != "%s" {
                    format!("{}", dt.and_utc().timestamp())
                } else {
                    format!("{}", dt.format("%Y-%m-%d %H:%M:%S"))
                }
            }
        };
        if !r.is_empty() {
            return Ok(r.to_string());
        }
    }
    Err(())
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        match self.time.clone() {
            None => println!("{}", Local::now().timestamp()),
            Some(ts) => {
                let mut result: Vec<String> = vec![];
                for t in ts {
                    match _execute(t, self.format.clone()) {
                        Ok(r) => result.push(r),
                        Err(_) => continue,
                    }
                }
                println!("{}", result.join("\n"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_none() {
        let _ = Cmd {
            format: None,
            time: None,
        }
        .execute()
        .await;
    }

    #[tokio::test]
    async fn test_execute_multi() {
        let args = Cmd {
            format: None,
            time: Some(vec![
                "1736441819".to_string(),
                "2025-02-07 18:30:00".to_string(),
                "2025-03-07T18:30:00".to_string(),
                "2025-04-07".to_string(),
            ]),
        };
        let _ = args.execute().await;
    }

    #[test]
    fn test_execute_ts() {
        assert!(_execute("1736441819".to_string(), None).is_ok());
    }

    #[test]
    fn test_execute_ts_format() {
        assert!(_execute("1736441819".to_string(), Some("%Y-%m-%d".to_string())).is_ok());
    }

    #[test]
    fn test_execute_datetime() {
        assert!(_execute("2025-02-07 18:30:00".to_string(), None).is_ok());
    }

    #[test]
    fn test_execute_datetime_t() {
        assert!(_execute("2025-03-07T18:30:00".to_string(), None).is_ok());
    }

    #[test]
    fn test_execute_date() {
        assert!(_execute("2025-03-07".to_string(), None).is_ok());
    }
}
