/**
 * 会员中心交互（仅界面行为，权限全部由 Worker 服务端判断）
 * - 移动端展开/收起导航
 * - 退出登录（调用服务端接口并清除会话）
 * - 复制带教微信
 */
(function () {
  var burger = document.getElementById("m-burger");
  var overlay = document.getElementById("m-overlay");

  function closeNav() {
    document.body.classList.remove("m-nav-open");
    if (burger) burger.setAttribute("aria-expanded", "false");
  }

  if (burger) {
    burger.addEventListener("click", function () {
      var open = document.body.classList.toggle("m-nav-open");
      burger.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  if (overlay) overlay.addEventListener("click", closeNav);

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeNav();
  });

  document.querySelectorAll(".m-nav a").forEach(function (link) {
    link.addEventListener("click", closeNav);
  });

  document.querySelectorAll("[data-logout]").forEach(function (button) {
    button.addEventListener("click", function () {
      button.disabled = true;
      fetch("/api/member/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" }
      })
        .catch(function () {
          /* 即使网络异常，也回到登录页，由服务端再次判定会话 */
        })
        .then(function () {
          location.href = "/member/";
        });
    });
  });

  // 只绑定显式复制按钮（data-copy-text），避免把导航文案配置键 data-copy 当成复制对象。
  document.querySelectorAll("[data-copy-text]").forEach(function (button) {
    button.addEventListener("click", function () {
      var text = button.getAttribute("data-copy-text") || "";
      var done = function () {
        var old = button.textContent;
        button.textContent = "已复制";
        setTimeout(function () {
          button.textContent = old;
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var input = document.createElement("input");
        input.value = text;
        document.body.appendChild(input);
        input.select();
        try {
          document.execCommand("copy");
        } catch (err) {
          /* 忽略复制失败 */
        }
        document.body.removeChild(input);
        done();
      }
    });
  });

  // 文章目录高亮当前阅读位置
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".m-toc a[href^='#']"));
  if (tocLinks.length && "IntersectionObserver" in window) {
    var map = {};
    tocLinks.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var target = document.getElementById(id);
      if (target) map[id] = link;
    });
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          tocLinks.forEach(function (link) {
            link.classList.remove("is-active");
          });
          var active = map[entry.target.id];
          if (active) active.classList.add("is-active");
        });
      },
      { rootMargin: "-88px 0px -66% 0px", threshold: 0 }
    );
    Object.keys(map).forEach(function (id) {
      observer.observe(document.getElementById(id));
    });
  }
})();
