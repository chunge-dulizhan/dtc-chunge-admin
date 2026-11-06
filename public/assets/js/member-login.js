/**
 * 会员访问码登录（第二阶段接入真实服务端验证）
 * 所有身份判断都在 Worker 端完成，这里只负责界面反馈。
 */
(function () {
  var form = document.getElementById("member-login-form");
  var input = document.getElementById("access-code");
  if (!form || !input) return;

  var alertBox = document.getElementById("login-alert");
  var alertText = alertBox ? alertBox.querySelector(".form-alert-text") : null;
  var submitBtn = form.querySelector('button[type="submit"]');
  var helper = document.querySelector(".login-helper");
  var divider = document.querySelector(".login-divider");

  function showAlert(message) {
    if (!alertBox) return;
    if (alertText) alertText.textContent = message;
    alertBox.classList.add("is-visible");
  }

  function clearAlert() {
    if (alertBox) alertBox.classList.remove("is-visible");
  }

  function safeNext() {
    var next = new URLSearchParams(location.search).get("next") || "";
    if (next.indexOf("/member/app/") === 0 || next.indexOf("/tools/") === 0) return next;
    return "/member/app/";
  }

  function showForm() {
    form.hidden = false;
    if (helper) helper.hidden = false;
    if (divider) divider.hidden = false;
  }

  // 页面加载时确认是否已有有效会话（刷新后仍然保持登录）
  fetch("/api/member/session", { credentials: "same-origin", headers: { Accept: "application/json" } })
    .then(function (res) {
      if (!res.ok) return null;
      return res.json();
    })
    .then(function (data) {
      if (!data || !data.ok) return;
      location.replace(safeNext());
    })
    .catch(function () {
      /* 网络异常时保持登录表单可用 */
    });

  // 输入时自动分段：vg8k29pxqm7d -> VG8K-29PX-QM7D
  input.addEventListener("input", function () {
    var raw = input.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
    var groups = raw.match(/.{1,4}/g);
    input.value = groups ? groups.join("-") : "";
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    clearAlert();

    var raw = input.value.toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (!raw) {
      showAlert("请输入会员访问码。");
      input.focus();
      return;
    }
    if (raw.length !== 12) {
      showAlert("访问码应为 12 位字符，请检查是否输入完整。");
      input.focus();
      return;
    }

    submitBtn.disabled = true;
    var originalText = submitBtn.textContent;
    submitBtn.textContent = "正在验证…";

    fetch("/api/member/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ code: raw })
    })
      .then(function (res) {
        return res.json().catch(function () {
          return { ok: false, message: "系统暂时无法验证，请稍后重试。" };
        }).then(function (data) {
          return { status: res.status, retry: res.headers.get("Retry-After"), data: data };
        });
      })
      .then(function (result) {
        if (result.data && result.data.ok) {
          location.replace(safeNext());
          return;
        }
        var message = (result.data && result.data.message) || "系统暂时无法验证，请稍后重试。";
        if (result.status === 429) {
          var wait = parseInt(result.retry || "60", 10);
          message = "尝试次数过多，请 " + Math.ceil(wait / 60) + " 分钟后再试。";
        }
        showAlert(message);
      })
      .catch(function () {
        showAlert("系统暂时无法验证，请稍后重试。");
      })
      .then(function () {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      });
  });

  var logoutBtn = document.getElementById("member-logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", function () {
      logoutBtn.disabled = true;
      fetch("/api/member/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
      })
        .then(function () {
          showForm();
          input.value = "";
          showAlert("已退出登录，如需再次进入请重新输入访问码。");
        })
        .catch(function () {
          showAlert("退出失败，请刷新页面后重试。");
        })
        .then(function () {
          logoutBtn.disabled = false;
        });
    });
  }
})();
