// Types related to QueryList and Watch API
use crate::pb;

use std::str::FromStr;
use std::string::ToString;

use anyhow::{anyhow, bail};
use serde::Serialize;
use strum::{Display, EnumString};

#[derive(Debug, Clone, Copy, Serialize, EnumString, Display)]
pub enum VMStatus {
    Running,
    PoweredOff,
    Paused,
}

impl Default for VMStatus {
    fn default() -> Self {
        VMStatus::Running
    }
}

#[derive(Debug, Clone, Copy, Serialize, EnumString, Display)]
pub enum TrustLevel {
    Secure,
    Warning,
    NotSecure,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Warning
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub name: String,        //VM name
    pub description: String, //App name, some details
    pub status: VMStatus,
    pub trust_level: TrustLevel,
}

impl QueryResult {
    pub fn parse_list(items: Vec<pb::QueryListItem>) -> anyhow::Result<Vec<QueryResult>> {
        let result = items
            .into_iter()
            .map(Self::try_from)
            .collect::<anyhow::Result<Vec<QueryResult>>>()?;
        Ok(result)
    }
}

impl TryFrom<pb::QueryListItem> for QueryResult {
    type Error = anyhow::Error;
    fn try_from(item: pb::QueryListItem) -> Result<QueryResult, Self::Error> {
        Ok(QueryResult {
            name: item.name,
            description: item.description,
            status: VMStatus::from_str(item.vm_status.as_str())?,
            trust_level: TrustLevel::from_str(item.trust_level.as_str())?,
        })
    }
}

impl Into<pb::QueryListItem> for QueryResult {
    fn into(self) -> pb::QueryListItem {
        pb::QueryListItem {
            name: self.name,
            description: self.description,
            vm_status: self.status.to_string(),
            trust_level: self.trust_level.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum Event {
    UnitStatusChanged(QueryResult), // When unit updated/added
    UnitRegistered(QueryResult),
    UnitShutdown(QueryResult),
}

impl Event {
    pub fn from_initial(item: pb::WatchItem) -> anyhow::Result<Vec<QueryResult>> {
        let status = item.status.ok_or_else(|| anyhow!("status field missing"))?;
        if let pb::admin::watch_item::Status::Initial(init) = status {
            QueryResult::parse_list(init.list)
        } else {
            bail!("Unexpected {status:?} instead of pb::admin::watch_item::Status::Initial")
        }
    }

    pub fn into_initial(items: Vec<QueryResult>) -> pb::WatchItem {
        let values = items.into_iter().map(|item| item.into()).collect();
        let init = pb::QueryListResponse { list: values };
        pb::WatchItem {
            status: Some(pb::admin::watch_item::Status::Initial(init)),
        }
    }

    #[inline]
    pub(crate) fn watch_item(status: pb::admin::watch_item::Status) -> pb::WatchItem {
        pb::WatchItem {
            status: Some(status),
        }
    }
}

impl TryFrom<pb::WatchItem> for Event {
    type Error = anyhow::Error;
    fn try_from(item: pb::WatchItem) -> Result<Self, Self::Error> {
        if let Some(status) = item.status {
            use pb::admin::watch_item::Status;
            Ok(match status {
                Status::Initial(_) => bail!("Unexpected repeated Status::Initial"),
                Status::Added(value) => Event::UnitRegistered(QueryResult::try_from(value)?),
                Status::Updated(value) => Event::UnitStatusChanged(QueryResult::try_from(value)?),
                Status::Removed(value) => Event::UnitShutdown(QueryResult::try_from(value)?),
            })
        } else {
            bail!("WatchItem missing")
        }
    }
}

impl Into<pb::WatchItem> for Event {
    fn into(self) -> pb::WatchItem {
        use pb::admin::watch_item::Status;
        match self {
            Event::UnitRegistered(value) => Self::watch_item(Status::Added(value.into())),
            Event::UnitStatusChanged(value) => Self::watch_item(Status::Updated(value.into())),
            Event::UnitShutdown(value) => Self::watch_item(Status::Removed(value.into())),
        }
    }
}
