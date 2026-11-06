/* ================================================================
   独立站春哥 · 会员工具页交互
   计算全部在服务端完成，前端只负责提交参数与渲染结果
   ================================================================ */

(function () {
  "use strict";

  var body = document.body;
  var tool = body.getAttribute("data-tool");
  var form = document.querySelector("[data-tool-form]");
  var result = document.querySelector("[data-role='result']");
  var alertBox = document.querySelector("[data-role='alert']");
  if (!tool || !form || !result) return;

  var submitBtn = form.querySelector("button[type='submit']");
  var submitLabel = submitBtn ? submitBtn.textContent : "";

  function node(tag, cls, text) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (text !== undefined) el.textContent = text;
    return el;
  }

  function showAlert(message) {
    if (!alertBox) return;
    alertBox.textContent = message;
    alertBox.hidden = false;
  }

  function clearAlert() {
    if (alertBox) alertBox.hidden = true;
  }

  function renderEmpty(text) {
    result.textContent = "";
    result.appendChild(node("div", "t-empty", text));
  }

  function renderResult(data) {
    var out = node("div", "t-output");

    if (data.headline) {
      var hl = node("div", "t-headline");
      hl.appendChild(node("span", "", data.headline.label || "计算结果"));
      hl.appendChild(node("b", "", String(data.headline.value || "")));
      if (data.headline.note) hl.appendChild(node("small", "", data.headline.note));
      out.appendChild(hl);
    }

    if (Array.isArray(data.items) && data.items.length) {
      var list = node("div", "t-list");
      data.items.forEach(function (item) {
        var row = node("div", "t-row");
        var label = node("div", "t-row-label", String(item.label || ""));
        if (item.note) label.appendChild(node("em", "", String(item.note)));
        row.appendChild(label);
        row.appendChild(node("div", "t-row-value", String(item.value || "")));
        list.appendChild(row);
      });
      out.appendChild(list);
    }

    if (Array.isArray(data.advice) && data.advice.length) {
      var advice = node("div", "t-advice");
      advice.appendChild(node("h3", "", "结论与下一步"));
      var ul = node("ul");
      data.advice.forEach(function (line) {
        ul.appendChild(node("li", "", String(line)));
      });
      advice.appendChild(ul);
      out.appendChild(advice);
    }

    if (data.prompt) {
      out.appendChild(node("div", "t-prompt", String(data.prompt)));
      var copy = node("button", "btn btn-ghost btn-sm t-copy", "复制这段提示词");
      copy.type = "button";
      copy.addEventListener("click", function () {
        var text = String(data.prompt);
        copyText(text).then(
          function () {
            copy.textContent = "已复制";
            setTimeout(function () {
              copy.textContent = "复制这段提示词";
            }, 2000);
          },
          function () {
            showAlert("浏览器未允许自动复制，请手动选中上方的提示词。");
          }
        );
      });
      out.appendChild(copy);
    }

    result.textContent = "";
    result.appendChild(out);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      try {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        var ok = document.execCommand("copy");
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error("copy_failed"));
      } catch (err) {
        reject(err);
      }
    });
  }

  function collect() {
    var payload = {};
    var data = new FormData(form);
    data.forEach(function (value, key) {
      payload[key] = value;
    });
    return payload;
  }

  function run() {
    clearAlert();
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = "计算中…";
    }
    renderEmpty("正在按当前参数计算…");

    fetch("/api/tools/" + tool + "/calc", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify(collect())
    })
      .then(function (res) {
        return res.json().then(function (data) {
          return { status: res.status, data: data };
        });
      })
      .then(function (payload) {
        var data = payload.data || {};
        if (payload.status === 401) {
          location.href = "/member/?next=" + encodeURIComponent(location.pathname + location.search);
          return;
        }
        if (payload.status === 403) {
          renderEmpty("当前会员权限暂不可用，请联系管理员核对会员状态后再试。");
          showAlert(data.message || "当前会员权限暂不可用。");
          return;
        }
        if (payload.status !== 200 || !data.ok) {
          renderEmpty("暂时无法完成计算，请检查参数后重试。");
          showAlert(data.message || "计算失败，请稍后重试。");
          return;
        }
        renderResult(data);
      })
      .catch(function () {
        renderEmpty("网络或服务暂时不可用，请稍后重试。");
        showAlert("网络或服务暂时不可用，请稍后重试。");
      })
      .then(function () {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = submitLabel;
        }
      });
  }

  // 货币单位联动（只影响金额字段右侧提示）
  var currency = form.querySelector("select[name='currency']");
  if (currency) {
    var syncCurrency = function () {
      var labels = form.querySelectorAll("[data-cur]");
      for (var i = 0; i < labels.length; i++) labels[i].textContent = currency.value;
    };
    currency.addEventListener("change", syncCurrency);
    syncCurrency();
  }

  // 节日日历默认显示当前月份
  var month = form.querySelector("select[name='month']");
  if (month) month.value = String(new Date().getMonth() + 1);

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    run();
  });

  renderEmpty("填写左侧参数后点击计算，结果会显示在这里。");
  run();
})();
