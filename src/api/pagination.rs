use serde::{Deserialize, Serialize};

/// Default number of items per page.
const DEFAULT_LIMIT: usize = 50;
/// Maximum number of items per page.
const MAX_LIMIT: usize = 200;

#[derive(Deserialize)]
pub struct PaginationParams {
    /// Base64-encoded cursor for the next page.
    pub cursor: Option<String>,
    /// Number of items per page (default 50, max 200).
    pub limit: Option<usize>,
}

impl PaginationParams {
    pub fn effective_limit(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
    }

    /// Decode a cursor string (base64 of a plain text key).
    pub fn decode_cursor(&self) -> Option<String> {
        self.cursor.as_ref().and_then(|c| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, c)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
    }
}

#[derive(Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

impl<T: Serialize> PaginatedResponse<T> {
    /// Build a paginated response from a full sorted list.
    /// `key_fn` extracts the cursor key from each item.
    pub fn from_sorted(
        items: Vec<T>,
        cursor: Option<&str>,
        limit: usize,
        key_fn: impl Fn(&T) -> String,
    ) -> Self {
        let filtered: Vec<T> = if let Some(cursor_key) = cursor {
            items
                .into_iter()
                .skip_while(|item| key_fn(item).as_str() <= cursor_key)
                .collect()
        } else {
            items
        };

        let has_more = filtered.len() > limit;
        let page: Vec<T> = filtered.into_iter().take(limit).collect();
        let next_cursor = if has_more {
            page.last().map(|item| {
                use base64::Engine;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_fn(item))
            })
        } else {
            None
        };

        Self {
            data: page,
            next_cursor,
            has_more,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Item {
        name: String,
        value: u32,
    }

    #[test]
    fn test_paginated_response_first_page() {
        let items: Vec<Item> = (0..10)
            .map(|i| Item {
                name: format!("item_{:02}", i),
                value: i,
            })
            .collect();
        let resp = PaginatedResponse::from_sorted(items, None, 3, |i| i.name.clone());
        assert_eq!(resp.data.len(), 3);
        assert!(resp.has_more);
        assert!(resp.next_cursor.is_some());
    }

    #[test]
    fn test_paginated_response_last_page() {
        let items: Vec<Item> = (0..3)
            .map(|i| Item {
                name: format!("item_{:02}", i),
                value: i,
            })
            .collect();
        let resp = PaginatedResponse::from_sorted(items, None, 5, |i| i.name.clone());
        assert_eq!(resp.data.len(), 3);
        assert!(!resp.has_more);
        assert!(resp.next_cursor.is_none());
    }

    #[test]
    fn test_paginated_response_with_cursor() {
        let items: Vec<Item> = (0..10)
            .map(|i| Item {
                name: format!("item_{:02}", i),
                value: i,
            })
            .collect();
        let resp = PaginatedResponse::from_sorted(items, Some("item_04"), 3, |i| i.name.clone());
        assert_eq!(resp.data.len(), 3);
        assert_eq!(resp.data[0].name, "item_05");
    }
}
