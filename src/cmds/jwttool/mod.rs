//! @alias: jwt
//! @about: JWT tool with Print/Crack/Modify/Create

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use std::fs;

use crate::CmdExecute;

mod core;

pub use self::core::{jwt_crack, jwt_create, jwt_modify, jwt_print};

const DEFAULT_ALPHABET: &str = "abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// JWT tool with Print/Crack/Modify/Create
#[derive(Debug, Parser)]
#[clap(name = "jwttool")]
pub struct Cmd {
    #[command(subcommand)]
    pub command: SubCmd,
}

#[derive(Debug, Subcommand)]
pub enum SubCmd {
    /// Print JWT pretty
    #[clap(aliases = ["print", "p"])]
    Jwtp {
        /// JWT token
        #[arg(short, long)]
        token: Option<String>,

        /// JWT secret
        #[arg(short, long)]
        secret: Option<String>,

        /// JWT secret from file
        #[arg(long = "secret-file", alias = "sf")]
        secret_file: Option<String>,

        /// Token as positional argument
        #[arg()]
        token_arg: Option<String>,
    },

    /// Modify JWT
    #[clap(aliases = ["modify", "m"])]
    Jwtm {
        /// JWT token
        #[arg(short, long)]
        token: Option<String>,

        /// JWT secret
        #[arg(short, long)]
        secret: Option<String>,

        /// JWT secret from file
        #[arg(long = "secret-file", alias = "sf")]
        secret_file: Option<String>,

        /// Set none method and no signature (Deprecated)
        #[arg(short, long)]
        none: bool,

        /// Print result token
        #[arg(long)]
        print: bool,

        /// Set new method: <HS256|HS384|HS512>
        #[arg(short = 'm', long)]
        method: Option<String>,

        /// Modify or add claims (key=value)
        #[arg(short, long = "claims", value_parser = parse_key_value)]
        claims: Vec<(String, String)>,

        /// Modify or add headers (key=value)
        #[arg(short = 'H', long = "headers", value_parser = parse_key_value)]
        headers: Vec<(String, String)>,

        /// Token as positional argument
        #[arg()]
        token_arg: Option<String>,
    },

    /// Crack JWT secret
    #[clap(aliases = ["crack", "c"])]
    Jwtc {
        /// JWT token
        #[arg(short, long)]
        token: Option<String>,

        /// The alphabet for the brute force
        #[arg(short, long, default_value = DEFAULT_ALPHABET)]
        alphabet: String,

        /// Prefix to the secret
        #[arg(short, long, default_value = "")]
        prefix: String,

        /// Suffix to the secret
        #[arg(short, long, default_value = "")]
        suffix: String,

        /// The min length secret
        #[arg(short = 'm', long, default_value = "1")]
        minlen: usize,

        /// The max length secret
        #[arg(short = 'l', long, default_value = "6")]
        maxlen: usize,

        /// Token as positional argument
        #[arg()]
        token_arg: Option<String>,
    },

    /// Create/Generate JWT
    #[clap(aliases = ["generate", "create", "gen", "n", "g"])]
    Jwtg {
        /// JWT secret
        #[arg(short, long)]
        secret: Option<String>,

        /// JWT secret from file
        #[arg(long = "secret-file", alias = "sf")]
        secret_file: Option<String>,

        /// Set method: <HS256|HS384|HS512>
        #[arg(short = 'm', long, default_value = "HS256")]
        method: String,

        /// Claims (key=value)
        #[arg(short, long = "claims", value_parser = parse_key_value)]
        claims: Vec<(String, String)>,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].to_string(), s[pos + 1..].to_string()))
}

fn get_secret(secret: &Option<String>, secret_file: &Option<String>) -> String {
    if let Some(sf) = secret_file {
        if let Ok(content) = fs::read_to_string(sf) {
            return content.trim().to_string();
        }
    }
    secret.clone().unwrap_or_default()
}

fn get_token(token: &Option<String>, token_arg: &Option<String>) -> Result<String> {
    token
        .clone()
        .or_else(|| token_arg.clone())
        .ok_or_else(|| anyhow!("Token is required"))
}

impl CmdExecute for Cmd {
    async fn execute(&self) -> Result<()> {
        match &self.command {
            SubCmd::Jwtp {
                token,
                secret,
                secret_file,
                token_arg,
            } => {
                let token_str = get_token(token, token_arg)?;
                let secret_str = get_secret(secret, secret_file);
                let result = jwt_print(&token_str, &secret_str)?;
                println!("{result}");
            }

            SubCmd::Jwtm {
                token,
                secret,
                secret_file,
                none,
                print,
                method,
                claims,
                headers,
                token_arg,
            } => {
                let token_str = get_token(token, token_arg)?;
                let secret_str = get_secret(secret, secret_file);
                let headers_map: std::collections::HashMap<String, String> =
                    headers.iter().cloned().collect();
                let claims_map: std::collections::HashMap<String, String> =
                    claims.iter().cloned().collect();
                let method_str = method.as_deref().unwrap_or("");

                let result = jwt_modify(
                    &token_str,
                    *none,
                    &secret_str,
                    &headers_map,
                    &claims_map,
                    method_str,
                    *print,
                )?;
                println!("{result}");
            }

            SubCmd::Jwtc {
                token,
                alphabet,
                prefix,
                suffix,
                minlen,
                maxlen,
                token_arg,
            } => {
                let token_str = get_token(token, token_arg)?;
                let result = jwt_crack(&token_str, *minlen, *maxlen, alphabet, prefix, suffix)?;
                println!("{result}");
            }

            SubCmd::Jwtg {
                secret,
                secret_file,
                method,
                claims,
            } => {
                let secret_str = get_secret(secret, secret_file);
                let claims_map: std::collections::HashMap<String, String> =
                    claims.iter().cloned().collect();
                let result = jwt_create(&claims_map, method, &secret_str)?;
                println!("{result}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_print() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c";
        let result = jwt_print(token, "").unwrap();
        println!("{result}");
        assert!(result.contains("foo"));
    }

    #[test]
    fn test_jwt_modify_none() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmlyaW5rIiwicm9sZSI6Imd1ZXN0In0.bPb06hMv6GA73WNOEO1D_HMyal6hS1ofBDIsRL3vszg";
        let mut claims = std::collections::HashMap::new();
        claims.insert("role".to_string(), "admin".to_string());
        let result = jwt_modify(
            token,
            true,
            "",
            &std::collections::HashMap::new(),
            &claims,
            "",
            false,
        )
        .unwrap();
        println!("{result}");
        assert!(result.starts_with("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."));
    }

    #[test]
    fn test_jwt_create() {
        let mut claims = std::collections::HashMap::new();
        claims.insert("name".to_string(), "test".to_string());
        let result = jwt_create(&claims, "HS256", "secret").unwrap();
        println!("{result}");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_jwt_crack() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoidmlyaW5rIn0.63La-xrRjx38xDkgrNHYfYHVgjB83bZsJMSa5luusgY";
        let result = jwt_crack(token, 4, 5, "abcdeijklvwxyz", "", "").unwrap();
        println!("Cracked secret: {result}");
        assert_eq!(result, "xkedd");
    }
}
