/*
 * Optional CodeMirror-backed editor for the custom-rules textarea on the
 * Suricata coverage page. Off by default; the plain textarea is the
 * fallback and the default experience.
 */
(function () {
  "use strict";

  var STORAGE_KEY = "dalton_suricata_rule_editor_enabled";
  var ENGINE_ANALYSIS_STORAGE_KEY = "dalton_suricata_engine_analysis_enabled";
  var KEYWORDS_URL = "/dalton/controller_api/rule_keywords";
  var CHECK_URL = "/dalton/controller_api/check_rules";
  var CHECK_DEBOUNCE_MS = 500;
  // Emitted once per rule by engine analysis; a classification, not
  // something to act on, and at one line per rule it buries everything
  // else. Filtered on the client so the linter stays a faithful proxy for
  // what the language server said.
  var FILTERED_MESSAGE_PATTERN = /^Rule type is /;
  var cm = null;
  var keywordsByName = null; // null until the first fetch resolves
  var hoverTooltip = null;
  var latestLintResults = []; // CodeMirror lint addon delivers this synchronously
  var checkDebounceTimer = null;

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

  function readEngineAnalysisPreference() {
    try {
      var stored = window.localStorage.getItem(ENGINE_ANALYSIS_STORAGE_KEY);
      return stored === null ? true : stored === "true";
    } catch (e) {
      return true;
    }
  }

  function writeEngineAnalysisPreference(enabled) {
    try {
      window.localStorage.setItem(
        ENGINE_ANALYSIS_STORAGE_KEY,
        enabled ? "true" : "false"
      );
    } catch (e) {
      // localStorage unavailable - preference just won't persist
    }
  }

  // LSP severities (1 Error, 2 Warning, 3 Info, 4 Hint) collapse to
  // CodeMirror's two gutter marker styles; the message text (shown in the
  // tooltip) still carries the real distinction.
  function lspSeverityToCmSeverity(severity) {
    return severity === 1 ? "error" : "warning";
  }

  function diagnosticToLintError(diag) {
    return {
      from: CodeMirror.Pos(diag.range.start.line, diag.range.start.character),
      to: CodeMirror.Pos(diag.range.end.line, diag.range.end.character),
      message: diag.message,
      severity: lspSeverityToCmSeverity(diag.severity),
    };
  }

  function runCheck() {
    if (!cm) {
      return;
    }
    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    var engineAnalysis = engineAnalysisCheckbox
      ? engineAnalysisCheckbox.checked
      : false;
    var body = JSON.stringify({
      rules: cm.getValue(),
      engine_analysis: engineAnalysis,
    });
    fetch(CHECK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body,
    })
      .then(function (resp) {
        return resp.json();
      })
      .then(function (data) {
        if (!data.available) {
          latestLintResults = [];
          if (cm) {
            cm.performLint();
          }
          return;
        }
        latestLintResults = (data.diagnostics || [])
          .filter(function (d) {
            return !FILTERED_MESSAGE_PATTERN.test(d.message);
          })
          .map(diagnosticToLintError);
        if (data.engine_version) {
          setStatus("checked against Suricata " + data.engine_version);
        }
        if (cm) {
          cm.performLint();
        }
      })
      .catch(function () {
        latestLintResults = [];
        if (cm) {
          cm.performLint();
        }
      });
  }

  function scheduleCheck() {
    if (checkDebounceTimer) {
      clearTimeout(checkDebounceTimer);
    }
    checkDebounceTimer = setTimeout(runCheck, CHECK_DEBOUNCE_MS);
  }

  // The lint addon's async mode aborts a pending result on any document
  // change (it registers its own "change" listener that bumps a
  // "waitingFor" id and drops anything that resolves after). Stashing the
  // updateLinting callback from getAnnotations and calling it whenever the
  // fetch above resolves would therefore deliver nothing, silently, the
  // request succeeds and the diagnostics are correct but nothing ever
  // renders. Instead: keep results in latestLintResults, have
  // getAnnotations deliver them synchronously every time CodeMirror asks,
  // and call cm.performLint() to trigger a fresh ask once a fetch
  // completes.
  function getAnnotations(text, updateLinting) {
    updateLinting(latestLintResults);
  }

  function updateEngineAnalysisVisibility(visible) {
    var label = document.getElementById("optionEngineAnalysisLabel");
    if (label) {
      label.style.display = visible ? "" : "none";
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
    latestLintResults = [];
    cm = CodeMirror.fromTextArea(textarea, {
      mode: "suricata",
      lineNumbers: true,
      lineWrapping: true,
      viewportMargin: Infinity,
      extraKeys: { "Ctrl-Space": "autocomplete" },
      hintOptions: { hint: suricataHint, completeSingle: false },
      gutters: ["CodeMirror-lint-markers"],
      lint: {
        async: true,
        lintOnChange: false,
        getAnnotations: getAnnotations,
      },
    });
    cm.getWrapperElement().addEventListener("mousemove", function (event) {
      onEditorMouseOver(cm, event);
    });
    cm.getWrapperElement().addEventListener("mouseleave", hideHoverTooltip);
    cm.on("changes", scheduleCheck);
    if (!keywordsByName) {
      fetchKeywords();
    }

    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    if (engineAnalysisCheckbox) {
      engineAnalysisCheckbox.checked = readEngineAnalysisPreference();
    }
    updateEngineAnalysisVisibility(true);
    runCheck();
  }

  function disableEditor() {
    if (!cm) {
      return;
    }
    if (checkDebounceTimer) {
      clearTimeout(checkDebounceTimer);
      checkDebounceTimer = null;
    }
    updateEngineAnalysisVisibility(false);
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

    var engineAnalysisCheckbox = document.getElementById("optionEngineAnalysis");
    if (engineAnalysisCheckbox) {
      engineAnalysisCheckbox.addEventListener("change", function () {
        writeEngineAnalysisPreference(engineAnalysisCheckbox.checked);
        // The user just asked to see something different - re-run now
        // rather than waiting for the next edit.
        runCheck();
      });
    }

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
