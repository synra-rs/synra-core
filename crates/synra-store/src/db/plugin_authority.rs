//! Durable UI authority revisions follow the facts in the same transaction, on every connection.

pub(super) const TRIGGERS: &str = r#"
CREATE TRIGGER plugin_authority_insert AFTER INSERT ON plugins BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_flags AFTER UPDATE OF enabled, trusted ON plugins BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_grant_insert AFTER INSERT ON plugin_grants BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_grant_update AFTER UPDATE ON plugin_grants BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_grant_delete AFTER DELETE ON plugin_grants BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = OLD.plugin_id;
END;
CREATE TRIGGER plugin_authority_version_insert AFTER INSERT ON plugin_versions WHEN NEW.active = 1 BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_version_update AFTER UPDATE ON plugin_versions WHEN OLD.active = 1 OR NEW.active = 1 BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = NEW.plugin_id;
END;
CREATE TRIGGER plugin_authority_version_delete AFTER DELETE ON plugin_versions WHEN OLD.active = 1 BEGIN
  UPDATE plugin_authority_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE plugins SET authority_revision = (SELECT revision FROM plugin_authority_clock WHERE id = 1)
    WHERE plugin_id = OLD.plugin_id;
END;
"#;
