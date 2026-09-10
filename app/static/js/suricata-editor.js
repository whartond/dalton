/*
 * Optional CodeMirror-backed editor for the custom-rules textarea on the
 * Suricata coverage page. Off by default; the plain textarea is the
 * fallback and the default experience.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "dalton_suricata_rule_editor_enabled";
  var cm = null;

  CodeMirror.defineSimpleMode("suricata", {
    start: [
      { regex: /#.*/, token: "comment" },
      {
        regex: /\b(?:alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth|log)\b/,
        token: "keyword",
        next: "header",
      },
    ],
    header: [
      { regex: /"(?:[^\\"]|\\.)*"/, token: "string" },
      { regex: /\$[A-Z_][A-Z0-9_]*/, token: "variable-2" },
      { regex: /->|<>/, token: "operator" },
      { regex: /\(/, token: "bracket", next: "options" },
      { regex: /[^\s()]+/, token: "atom" },
    ],
    options: [
      { regex: /#.*/, token: "comment" },
      { regex: /"(?:[^\\"]|\\.)*"/, token: "string" },
      // Any word immediately followed by ':' or ';' is treated as an option
      // name, rather than matching against an enumerated keyword list, so
      // keywords the completion data has never heard of still colour
      // correctly.
      { regex: /[a-zA-Z_][\w.]*(?=\s*[:;])/, token: "attribute" },
      { regex: /;/, token: "operator" },
      { regex: /\)/, token: "bracket", next: "start" },
      { regex: /[^\s;)"]+/, token: null },
    ],
    meta: { lineComment: "#" },
  });

  function readStoredPreference() {
    try {
      return window.localStorage.getItem(STORAGE_KEY) === "true";
    } catch (e) {
      return false;
    }
  }

  function writeStoredPreference(enabled) {
    try {
      window.localStorage.setItem(STORAGE_KEY, enabled ? "true" : "false");
    } catch (e) {
      // localStorage unavailable (e.g. private browsing) - preference just
      // won't persist across reloads.
    }
  }

  function enableEditor() {
    if (cm) {
      return;
    }
    var textarea = document.querySelector('textarea[name="custom_ruleset"]');
    if (!textarea) {
      return;
    }
    cm = CodeMirror.fromTextArea(textarea, {
      mode: "suricata",
      lineNumbers: true,
      lineWrapping: true,
      viewportMargin: Infinity,
    });
  }

  function disableEditor() {
    if (!cm) {
      return;
    }
    cm.toTextArea();
    cm = null;
  }

  function setEnabled(enabled) {
    if (enabled) {
      enableEditor();
    } else {
      disableEditor();
    }
    writeStoredPreference(enabled);
  }

  // The custom-rules box lives in a <span> that gets shown/hidden by
  // coverage.html. CodeMirror measures itself incorrectly if it's
  // constructed or left sitting inside a hidden container - call this
  // whenever that span is revealed.
  function refresh() {
    if (cm) {
      cm.refresh();
    }
  }

  function init() {
    var checkbox = document.getElementById("optionRuleEditor");
    if (!checkbox) {
      return;
    }

    var enabled = readStoredPreference();
    checkbox.checked = enabled;
    if (enabled) {
      enableEditor();
    }

    checkbox.addEventListener("change", function () {
      setEnabled(checkbox.checked);
    });

    // CodeMirror only syncs back to the underlying textarea on toTextArea()
    // (or an explicit save()) - without this, submitting the form while the
    // editor is active would send whatever was in the textarea at
    // construction time, not the edited content.
    document.getElementById("submitjob").addEventListener("submit", function () {
      if (cm) {
        cm.save();
      }
    });
  }

  window.SuricataEditor = {
    init: init,
    refresh: refresh,
  };
})();
