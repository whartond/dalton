/*
 * Optional CodeMirror-backed editor for the custom-rules textarea on the
 * Suricata coverage page. Off by default; the plain textarea is the
 * fallback and the default experience.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "dalton_suricata_rule_editor_enabled";
  var KEYWORDS_URL = "/dalton/controller_api/rule_keywords";
  var cm = null;
  var keywordsByName = null; // null until the first fetch resolves
  var hoverTooltip = null;

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

  function setStatus(text) {
    var status = document.getElementById("ruleEditorStatus");
    if (status) {
      status.textContent = text;
    }
  }

  function fetchKeywords() {
    fetch(KEYWORDS_URL, { headers: { Accept: "application/json" } })
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        if (!data.available || !data.keywords) {
          // Fall back to whatever was already loaded (possibly nothing)
          // rather than showing an empty completion popup.
          if (!keywordsByName) {
            setStatus("");
          }
          return;
        }
        keywordsByName = {};
        data.keywords.forEach(function (kw) {
          keywordsByName[kw.name] = kw;
        });
        var status = "keywords from Suricata " + data.engine_version;
        if (data.stale) {
          status += " (cached; linter unavailable)";
        }
        setStatus(status);
      })
      .catch(function () {
        if (!keywordsByName) {
          setStatus("");
        }
      });
  }

  // Word immediately before the cursor, matching how the mode tokenizes
  // option names (letters/digits/underscore/dot).
  function currentWordRange(cm, cursor) {
    var line = cm.getLine(cursor.line);
    var start = cursor.ch;
    var end = cursor.ch;
    while (start > 0 && /[\w.]/.test(line.charAt(start - 1))) {
      start--;
    }
    while (end < line.length && /[\w.]/.test(line.charAt(end))) {
      end++;
    }
    return {
      text: line.slice(start, end),
      from: CodeMirror.Pos(cursor.line, start),
      to: CodeMirror.Pos(cursor.line, end),
    };
  }

  function suricataHint(cm) {
    if (!keywordsByName) {
      return null;
    }
    var cursor = cm.getCursor();
    var word = currentWordRange(cm, cursor);
    var prefix = word.text.toLowerCase();
    var matches = Object.keys(keywordsByName)
      .filter(function (name) {
        return prefix.length === 0 || name.toLowerCase().indexOf(prefix) === 0;
      })
      .sort()
      .map(function (name) {
        var kw = keywordsByName[name];
        var display = kw.legacy_for ? name + " (legacy for " + kw.legacy_for + ")" : name;
        return { text: name, displayText: display };
      });
    if (matches.length === 0) {
      return null;
    }
    return { list: matches, from: word.from, to: word.to };
  }

  function hideHoverTooltip() {
    if (hoverTooltip) {
      hoverTooltip.remove();
      hoverTooltip = null;
    }
  }

  function showHoverTooltip(cm, pos, coords, kw) {
    hideHoverTooltip();
    var el = document.createElement("div");
    el.className = "suricata-editor-tooltip";
    el.style.cssText =
      "position:absolute;z-index:10;max-width:420px;padding:6px 10px;" +
      "background:#333;color:#fff;font-size:12px;border-radius:3px;" +
      "box-shadow:0 1px 4px rgba(0,0,0,0.4);";
    // kw.description already notes "(legacy name for 'X')" for aliases -
    // see legacy_keywords.py - so nothing to add here.
    el.textContent = kw.description || "";
    if (kw.documentation) {
      el.appendChild(document.createElement("br"));
      var link = document.createElement("a");
      link.href = kw.documentation;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.style.color = "#9cf";
      link.textContent = kw.documentation;
      el.appendChild(link);
    }
    document.body.appendChild(el);
    // coords is in "page" mode (document-relative, scroll already baked
    // in) since position:absolute here is relative to the document too.
    el.style.left = coords.right + 8 + "px";
    el.style.top = coords.top + "px";
    hoverTooltip = el;
  }

  function onEditorMouseOver(cm, event) {
    if (!keywordsByName) {
      return;
    }
    var pos = cm.coordsChar(
      { left: event.clientX, top: event.clientY },
      "window"
    );
    var token = cm.getTokenAt(pos);
    if (token.type !== "attribute") {
      hideHoverTooltip();
      return;
    }
    var kw = keywordsByName[token.string];
    if (!kw) {
      hideHoverTooltip();
      return;
    }
    showHoverTooltip(cm, pos, cm.charCoords(pos, "page"), kw);
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
      extraKeys: { "Ctrl-Space": "autocomplete" },
      hintOptions: { hint: suricataHint, completeSingle: false },
    });
    cm.getWrapperElement().addEventListener("mousemove", function (event) {
      onEditorMouseOver(cm, event);
    });
    cm.getWrapperElement().addEventListener("mouseleave", hideHoverTooltip);
    if (!keywordsByName) {
      fetchKeywords();
    }
  }

  function disableEditor() {
    if (!cm) {
      return;
    }
    hideHoverTooltip();
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
