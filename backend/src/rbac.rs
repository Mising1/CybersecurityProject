use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { Administrator, Kierownik, Redaktor, Czytelnik }

#[derive(Clone, Copy, PartialEq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ManageUsers, ManageSettings,      // panel administratora
    ReadContent, EditContent, ApproveContent,
}

impl Permission {
    pub const ALL: [Permission; 5] =
        [Self::ManageUsers, Self::ManageSettings, Self::ReadContent, Self::EditContent, Self::ApproveContent];
}

impl Role {
    /// Jedyne miejsce, w którym role dostają uprawnienia - kod sprawdza uprawnienia, nigdy role.
    pub fn has(self, p: Permission) -> bool {
        use Permission::*;
        match self {
            Role::Administrator => matches!(p, ManageUsers | ManageSettings),
            Role::Kierownik     => matches!(p, ReadContent | EditContent | ApproveContent),
            Role::Redaktor      => matches!(p, ReadContent | EditContent),
            Role::Czytelnik     => matches!(p, ReadContent),
        }
    }

    pub fn permissions(self) -> Vec<Permission> {
        Permission::ALL.into_iter().filter(|&p| self.has(p)).collect()
    }
}
