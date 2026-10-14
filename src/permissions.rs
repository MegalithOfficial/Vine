use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Pattern matching for permission nodes.
///
/// Supports:
/// - `*` matches everything
/// - Exact match (`vine.command.send` matches `vine.command.send`)
/// - Wildcard suffix (`vine.command.*` matches `vine.command.send` and `vine.command.server`)
/// - Case-insensitive matching
pub fn matches_node(pattern: &str, target: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let t = target.to_ascii_lowercase();

    if p == "*" || p == t {
        return true;
    }

    if let Some(prefix) = p.strip_suffix(".*")
        && t.starts_with(prefix)
    {
        // Must match boundary e.g. "vine.command.*" matches "vine.command.send" but not "vine.commander"
        if t.len() > prefix.len() && t.as_bytes()[prefix.len()] == b'.' {
            return true;
        }
    }

    false
}

/// Configuration for a permission group
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupConfig {
    /// Groups inherited by this group
    #[serde(default)]
    pub inherits: Vec<String>,
    /// List of permission nodes (e.g. `["vine.command.server", "*", "-vine.command.send"]`)
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// User assignment configuration (either a simple list of groups or detailed with direct permissions)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum UserPermissionConfig {
    /// Simple group list: e.g. `"Alex" = ["admin"]`
    Groups(Vec<String>),
    /// Detailed configuration with both groups and direct permissions
    Detailed {
        #[serde(default)]
        groups: Vec<String>,
        #[serde(default)]
        permissions: Vec<String>,
    },
}

impl UserPermissionConfig {
    pub fn groups(&self) -> &[String] {
        match self {
            Self::Groups(groups) => groups,
            Self::Detailed { groups, .. } => groups,
        }
    }

    pub fn direct_permissions(&self) -> &[String] {
        match self {
            Self::Groups(_) => &[],
            Self::Detailed { permissions, .. } => permissions,
        }
    }
}

fn default_group_name() -> String {
    "default".to_string()
}

fn default_permission_groups() -> HashMap<String, GroupConfig> {
    let mut groups = HashMap::new();
    groups.insert(
        "default".to_string(),
        GroupConfig {
            inherits: Vec::new(),
            permissions: vec![
                "vine.command.server".to_string(),
                "vine.command.glist".to_string(),
                "vine.command.list".to_string(),
                "vine.command.help".to_string(),
            ],
        },
    );
    groups.insert(
        "admin".to_string(),
        GroupConfig {
            inherits: vec!["default".to_string()],
            permissions: vec![
                "vine.command.send".to_string(),
                "vine.admin".to_string(),
                "*".to_string(),
            ],
        },
    );
    groups
}

/// Configuration for the proxy permission system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PermissionsConfig {
    /// Default group applied to every player (default: "default")
    #[serde(default = "default_group_name")]
    pub default_group: String,
    /// Permission groups with inheritance and node lists
    #[serde(default = "default_permission_groups")]
    pub groups: HashMap<String, GroupConfig>,
    /// User assignments mapping username to groups or direct permissions
    #[serde(default)]
    pub users: HashMap<String, UserPermissionConfig>,
}

impl Default for PermissionsConfig {
    fn default() -> Self {
        Self {
            default_group: default_group_name(),
            groups: default_permission_groups(),
            users: HashMap::new(),
        }
    }
}

impl PermissionsConfig {
    /// Collects all effective permission strings for a given username,
    /// resolving direct permissions, group inheritance, and default group.
    pub fn collect_permissions(&self, username: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut user_groups = Vec::new();

        // 1. Direct user configuration (case-insensitive username lookup)
        if let Some((_, user_cfg)) = self
            .users
            .iter()
            .find(|(u, _)| u.eq_ignore_ascii_case(username))
        {
            for perm in user_cfg.direct_permissions() {
                result.push(perm.clone());
            }
            for grp in user_cfg.groups() {
                user_groups.push(grp.as_str());
            }
        }

        // Always include default_group unless explicitly overridden
        if !user_groups
            .iter()
            .any(|g| g.eq_ignore_ascii_case(&self.default_group))
        {
            user_groups.push(&self.default_group);
        }

        // 3. Resolve groups with inheritance
        let mut visited_groups = HashSet::new();
        let mut queue = VecDeque::from(user_groups);

        while let Some(grp_name) = queue.pop_front() {
            let grp_lower = grp_name.to_ascii_lowercase();
            if !visited_groups.insert(grp_lower.clone()) {
                continue;
            }

            if let Some((_, grp)) = self
                .groups
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&grp_lower))
            {
                for perm in &grp.permissions {
                    result.push(perm.clone());
                }
                for inherit in &grp.inherits {
                    queue.push_back(inherit.as_str());
                }
            }
        }

        result
    }

    /// Evaluates whether a user has the specified permission node.
    ///
    /// Evaluation rules:
    /// 1. If any effective permission starts with `-` and matches `node`, access is explicitly denied (returns `false`).
    /// 2. If any positive effective permission matches `node` (exact, wildcard `*`, or prefix `foo.*`), returns `true`.
    /// 3. Otherwise returns `false`.
    pub fn has_permission(&self, username: &str, node: &str) -> bool {
        let perms = self.collect_permissions(username);

        // 1. Check explicit negations first
        for perm in &perms {
            if let Some(negated) = perm.strip_prefix('-')
                && matches_node(negated, node)
            {
                return false;
            }
        }

        // 2. Check positive permissions
        for perm in &perms {
            if !perm.starts_with('-') && matches_node(perm, node) {
                return true;
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_node() {
        assert!(matches_node("*", "vine.command.send"));
        assert!(matches_node("vine.command.send", "vine.command.send"));
        assert!(matches_node("VINE.COMMAND.SEND", "vine.command.send"));
        assert!(matches_node("vine.command.*", "vine.command.send"));
        assert!(matches_node("vine.command.*", "vine.command.server"));
        assert!(!matches_node("vine.command.*", "vine.commander"));
        assert!(!matches_node("vine.command.*", "other.command.send"));
    }

    #[test]
    fn test_default_permissions() {
        let mut config = PermissionsConfig::default();
        assert!(config.users.is_empty());

        // Regular player in default group
        assert!(config.has_permission("Steve", "vine.command.server"));
        assert!(config.has_permission("Steve", "vine.command.glist"));
        assert!(config.has_permission("Steve", "vine.command.list"));
        assert!(config.has_permission("Steve", "vine.command.help"));
        assert!(!config.has_permission("Steve", "vine.command.send"));
        assert!(!config.has_permission("Steve", "vine.admin"));

        // Alex in admin group
        config.users.insert(
            "Alex".to_string(),
            UserPermissionConfig::Groups(vec!["admin".to_string()]),
        );
        assert!(config.has_permission("Alex", "vine.command.send"));
        assert!(config.has_permission("alex", "vine.command.send")); // case-insensitive
        assert!(config.has_permission("Alex", "vine.command.server"));
        assert!(config.has_permission("Alex", "any.random.node")); // * wildcard
    }

    #[test]
    fn test_negated_permissions() {
        let mut config = PermissionsConfig::default();
        let mut groups = HashMap::new();
        groups.insert(
            "moderator".to_string(),
            GroupConfig {
                inherits: vec!["default".to_string()],
                permissions: vec![
                    "vine.command.*".to_string(),
                    "-vine.command.send".to_string(),
                ],
            },
        );
        config.groups = groups;
        config.users.insert(
            "ModUser".to_string(),
            UserPermissionConfig::Groups(vec!["moderator".to_string()]),
        );

        assert!(config.has_permission("ModUser", "vine.command.server"));
        assert!(config.has_permission("ModUser", "vine.command.glist"));
        // Explicitly negated
        assert!(!config.has_permission("ModUser", "vine.command.send"));
    }

    #[test]
    fn test_circular_group_inheritance_does_not_loop() {
        let mut config = PermissionsConfig::default();
        let mut groups = HashMap::new();
        groups.insert(
            "group_a".to_string(),
            GroupConfig {
                inherits: vec!["group_b".to_string()],
                permissions: vec!["node.a".to_string()],
            },
        );
        groups.insert(
            "group_b".to_string(),
            GroupConfig {
                inherits: vec!["group_a".to_string()],
                permissions: vec!["node.b".to_string()],
            },
        );
        config.groups = groups;
        config.users.insert(
            "User1".to_string(),
            UserPermissionConfig::Groups(vec!["group_a".to_string()]),
        );

        assert!(config.has_permission("User1", "node.a"));
        assert!(config.has_permission("User1", "node.b"));
    }

    #[test]
    fn test_detailed_user_config() {
        let mut config = PermissionsConfig::default();
        config.users.insert(
            "CustomUser".to_string(),
            UserPermissionConfig::Detailed {
                groups: vec!["default".to_string()],
                permissions: vec!["custom.perm".to_string()],
            },
        );

        assert!(config.has_permission("CustomUser", "custom.perm"));
        assert!(config.has_permission("CustomUser", "vine.command.server"));
        assert!(!config.has_permission("CustomUser", "vine.command.send"));
    }
}
