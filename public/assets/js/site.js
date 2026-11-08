/* ================================================================
   独立站春哥 · 站点交互脚本
   仅包含界面交互，不包含任何会员权限判断逻辑。
   会员校验将在第二阶段由服务端（Cloudflare Worker）完成。
   ================================================================ */
(function () {
  "use strict";

  document.documentElement.classList.add("js");

  /* ---------- Toast ---------- */
  var toastEl = null;
  var toastTimer = null;

  function showToast(message) {
    if (!toastEl) {
      toastEl = document.createElement("div");
      toastEl.className = "toast";
      toastEl.setAttribute("role", "status");
      document.body.appendChild(toastEl);
    }
    toastEl.textContent = message;
    // 强制重绘，保证连续点击时动效正常
    void toastEl.offsetWidth;
    toastEl.classList.add("is-visible");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      toastEl.classList.remove("is-visible");
    }, 2200);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        document.body.removeChild(area);
      }
    });
  }

  // 只处理显式的复制按钮（data-copy-text），绝不拦截普通导航链接。
  // data-copy 是服务端文案配置键，不属于客户端交互标记。
  document.addEventListener("click", function (event) {
    var trigger = event.target.closest("[data-copy-text]");
    if (!trigger) return;
    event.preventDefault();
    var value = trigger.getAttribute("data-copy-text") || "";
    copyText(value).then(
      function () {
        showToast("已复制：" + value);
      },
      function () {
        showToast("复制失败，请手动记录：" + value);
      }
    );
  });

  /* ---------- 顶部滚动状态 ---------- */
  var header = document.querySelector(".site-header");

  function syncHeader() {
    if (!header) return;
    header.classList.toggle("is-scrolled", window.scrollY > 8);
  }

  window.addEventListener("scroll", syncHeader, { passive: true });
  syncHeader();

  /* ---------- 移动端菜单 ---------- */
  var navToggle = document.querySelector(".nav-toggle");
  var mobileNav = document.querySelector(".mobile-nav");

  function closeMobileNav() {
    if (!navToggle || !mobileNav) return;
    navToggle.setAttribute("aria-expanded", "false");
    mobileNav.classList.remove("is-open");
    document.body.style.removeProperty("overflow");
  }

  if (navToggle && mobileNav) {
    navToggle.addEventListener("click", function () {
      var open = navToggle.getAttribute("aria-expanded") === "true";
      if (open) {
        closeMobileNav();
      } else {
        navToggle.setAttribute("aria-expanded", "true");
        mobileNav.classList.add("is-open");
        document.body.style.overflow = "hidden";
      }
    });

    mobileNav.addEventListener("click", function (event) {
      if (event.target.closest("a")) closeMobileNav();
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closeMobileNav();
    });

    window.addEventListener("resize", function () {
      if (window.innerWidth > 900) closeMobileNav();
    });
  }

  /* ---------- 进入视口渐显 ---------- */
  var reveals = Array.prototype.slice.call(document.querySelectorAll(".reveal"));

  if ("IntersectionObserver" in window && reveals.length) {
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            observer.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.12 }
    );

    reveals.forEach(function (el) {
      observer.observe(el);
    });
  } else {
    reveals.forEach(function (el) {
      el.classList.add("is-in");
    });
  }

  /* ---------- 文章目录高亮 ---------- */
  var tocLinks = Array.prototype.slice.call(
    document.querySelectorAll(".toc-list a[href^='#'], .m-toc a[href^='#']")
  );

  if (tocLinks.length) {
    var sections = tocLinks
      .map(function (link) {
        var id = link.getAttribute("href").slice(1);
        return { link: link, el: document.getElementById(id) };
      })
      .filter(function (item) {
        return item.el;
      });

    var ticking = false;

    function syncToc() {
      ticking = false;
      var offset = (header ? header.offsetHeight : 76) + 40;
      var current = sections[0];
      sections.forEach(function (item) {
        if (item.el.getBoundingClientRect().top <= offset) current = item;
      });
      tocLinks.forEach(function (link) {
        link.classList.remove("is-active");
      });
      if (current) current.link.classList.add("is-active");
    }

    window.addEventListener(
      "scroll",
      function () {
        if (!ticking) {
          ticking = true;
          window.requestAnimationFrame(syncToc);
        }
      },
      { passive: true }
    );

    syncToc();
  }

  /* ---------- 会员访问码输入格式化 ---------- */
  var codeInput = document.getElementById("access-code");

  if (codeInput) {
    codeInput.addEventListener("input", function () {
      var raw = codeInput.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
      var groups = raw.match(/.{1,4}/g);
      codeInput.value = groups ? groups.join("-") : "";
    });
  }

  /* ---------- 首页学员案例（与后台案例管理同一套数据） ---------- */
  var caseGrid = document.getElementById("home-case-grid");
  var caseSection = document.getElementById("home-cases-section");

  if (caseGrid && caseSection) {
    var escCase = function (value) {
      return String(value === null || value === undefined ? "" : value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    };
    fetch("/api/public/cases", { credentials: "same-origin" })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (data) {
        var items = data && data.ok && Array.isArray(data.items) ? data.items : [];
        if (!items.length) return; // 没有已发布案例时保持板块隐藏
        caseGrid.innerHTML = items
          .map(function (item) {
            var cover = item.cover_image
              ? '<img src="' + escCase(item.cover_image) + '" alt="' + escCase(item.title) + '" loading="lazy">'
              : "";
            return (
              '<a class="case-card" href="/cases/' + escCase(item.slug) + '/">' +
              '<div class="case-top">' + cover + "</div>" +
              '<span class="case-niche">' + escCase(item.category || "学员案例") + "</span>" +
              "<h3>" + escCase(item.title) + "</h3>" +
              (item.summary ? '<p class="case-quote">' + escCase(item.summary) + "</p>" : "") +
              '<span class="case-card-go">查看案例 →</span>' +
              "</a>"
            );
          })
          .join("");
        caseSection.hidden = false;
      })
      .catch(function () {
        // 接口异常时保持板块隐藏，不影响首页其他内容
      });
  }

  /* ---------- 登录表单（第一阶段仅界面演示） ---------- */
  var loginForm = document.getElementById("member-login-form");

  if (loginForm) {
    var alertBox = document.getElementById("login-alert");

    function showAlert(text) {
      if (!alertBox) return;
      alertBox.querySelector(".form-alert-text").textContent = text;
      alertBox.classList.add("is-visible");
    }

    loginForm.addEventListener("submit", function (event) {
      event.preventDefault();
      var value = codeInput ? codeInput.value.trim() : "";
      var compact = value.replace(/-/g, "");

      if (!compact) {
        showAlert("请输入会员访问码");
        return;
      }

      if (compact.length !== 12) {
        showAlert("访问码格式为 12 位字符，形如 VG8K-29PX-QM7D，请检查后重试。");
        return;
      }

      showAlert("当前为第一阶段演示环境：访问码验证服务将在第二阶段接入，本页面暂不执行真实登录。");
    });
  }
})();
