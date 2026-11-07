/**
 * 独立站春哥 · 管理后台交互
 * 所有权限与数据校验都在 Cloudflare Worker 服务端完成，
 * 本文件只负责表单提交、列表渲染与弹层交互。
 */
(function () {
  "use strict";

  var page = document.body.getAttribute("data-page");
  var $ = function (selector, root) {
    return (root || document).querySelector(selector);
  };
  var $$ = function (selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  };

  function esc(value) {
    return String(value === null || value === undefined ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmt(iso) {
    if (!iso) return "—";
    var s = String(iso);
    var date = s.slice(0, 10);
    var time = s.length > 11 ? s.slice(11, 16) : "";
    return time ? date + " " + time : date;
  }

  function statusTag(status) {
    var map = {
      active: "正常",
      paused: "已暂停",
      disabled: "已停用",
      published: "已发布",
      draft: "草稿",
      archived: "已下架",
    };
    return '<span class="a-tag ' + esc(status) + '">' + esc(map[status] || status) + "</span>";
  }

  function accessTag(level) {
    return level === "free"
      ? '<span class="a-tag free">免费</span>'
      : '<span class="a-tag member">会员</span>';
  }

  var toastTimer = null;
  function toast(message, isError) {
    var el = $("#a-toast");
    if (!el) return;
    el.textContent = message;
    el.className = "a-toast show" + (isError ? " error" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      el.className = "a-toast";
    }, 2600);
  }

  async function api(path, options) {
    var opt = options || {};
    var init = {
      method: opt.method || "GET",
      credentials: "same-origin",
      headers: {},
    };
    if (opt.body) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opt.body);
    }
    var res = await fetch(path, init);
    var data = null;
    try {
      data = await res.json();
    } catch (err) {
      data = null;
    }
    if (res.status === 401) {
      location.href = "/admin/";
      throw new Error("登录状态已失效");
    }
    if (!res.ok || !data || data.ok === false) {
      var error = new Error((data && data.message) || "请求失败，请稍后重试。");
      error.status = res.status;
      error.code = data && data.error;
      throw error;
    }
    return data;
  }

  function showAlert(el, message, ok) {
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    el.className = "a-form-alert" + (ok ? " ok" : "");
  }

  function hideAlert(el) {
    if (el) el.hidden = true;
  }

  function bindDialogBasics() {
    $$("[data-close-dialog]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var dialog = btn.closest("dialog");
        if (dialog) dialog.close();
      });
    });
    $$(".a-dialog").forEach(function (dialog) {
      dialog.addEventListener("click", function (event) {
        if (event.target === dialog) dialog.close();
      });
    });
    $$("[data-admin-logout]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        btn.disabled = true;
        fetch("/api/admin/logout", { method: "POST", credentials: "same-origin" })
          .catch(function () {})
          .then(function () {
            location.href = "/admin/";
          });
      });
    });
  }

  /* ---------------- 登录 / 初始化 ---------------- */

  function initAuth() {
    var form = $("#admin-auth-form");
    var alertEl = $("#admin-auth-alert");
    var submit = $("#admin-auth-submit");
    if (!form) return;

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      hideAlert(alertEl);
      submit.disabled = true;

      var fd = new FormData(form);
      var username = String(fd.get("username") || "").trim();
      var password = String(fd.get("password") || "");
      var setupToken = String(fd.get("setup_token") || "");

      try {
        if (page === "setup") {
          var payload = { username: username, password: password };
          if (setupToken) payload.setup_token = setupToken;
          await api("/api/admin/setup", { method: "POST", body: payload });
          await api("/api/admin/login", { method: "POST", body: { username: username, password: password } });
          location.href = "/admin/";
          return;
        }
        await api("/api/admin/login", { method: "POST", body: { username: username, password: password } });
        location.href = "/admin/";
      } catch (err) {
        showAlert(alertEl, err.message);
        submit.disabled = false;
      }
    });
  }

  /* ---------------- 概览 ---------------- */

  async function initOverview() {
    try {
      var data = await api("/api/admin/overview");

      var stats = $("[id=overview-stats]") || $("#overview-stats");
      if (stats) {
        stats.innerHTML =
          '<div class="a-stat"><span>会员总数</span><b>' + data.members.total + "</b><small>正常 " +
          data.members.active + " · 暂停 " + data.members.paused + " · 停用 " + data.members.disabled + "</small></div>" +
          '<div class="a-stat"><span>已发布课程</span><b>' + data.contents.published + "</b><small>草稿 " +
          data.contents.draft + " · 下架 " + data.contents.archived + "</small></div>" +
          '<div class="a-stat"><span>可下载资料</span><b>' + data.resources + "</b><small>仅统计已发布</small></div>" +
          '<div class="a-stat"><span>网页工具</span><b>' + data.tools + "</b><small>第五轮接入受保护入口</small></div>";
      }

      var auditBox = $("#overview-audit");
      if (auditBox) {
        auditBox.innerHTML = data.recent.length
          ? data.recent
              .map(function (row) {
                return '<div class="a-audit-row"><time>' + esc(fmt(row.created_at)) + "</time><div><b>" +
                  esc(row.action) + "</b><p>" + esc(row.detail || "—") + "</p></div></div>";
              })
              .join("")
          : '<p class="a-empty">暂无操作记录。</p>';
      }
    } catch (err) {
      toast(err.message, true);
    }
  }

  /* ---------------- 会员管理 ---------------- */

  var memberState = { q: "", status: "", page: 1, pageSize: 20 };

  function renderMembers(data) {
    var rows = $("#member-rows");
    if (!rows) return;

    if (!data.items.length) {
      rows.innerHTML = '<tr><td colspan="7" class="a-empty">没有符合条件的会员。</td></tr>';
    } else {
      rows.innerHTML = data.items
        .map(function (m) {
          var subParts = [];
          if (m.contact) subParts.push("联系方式：" + m.contact);
          if (m.wechat_note) subParts.push("微信：" + m.wechat_note);
          if (m.notes) subParts.push("备注：" + m.notes);

          var actions =
            '<button class="a-mini" data-act="rotate" data-id="' + m.id + '">重置访问码</button>' +
            (m.status === "active"
              ? '<button class="a-mini" data-act="pause" data-id="' + m.id + '">暂停</button>'
              : '<button class="a-mini" data-act="resume" data-id="' + m.id + '">恢复</button>') +
            (m.status !== "disabled"
              ? '<button class="a-mini danger" data-act="disable" data-id="' + m.id + '">停用</button>'
              : "") +
            '<button class="a-mini" data-act="revoke" data-id="' + m.id + '">下线所有会话</button>' +
            '<button class="a-mini danger" data-act="delete" data-id="' + m.id + '">删除</button>';

          return '<tr><td><span class="a-mono">' + esc(m.member_code) + "</span></td>" +
            "<td><span class=\"a-cell-title\">" + esc(m.name) + '</span>' +
            (subParts.length ? '<span class="a-cell-sub">' + esc(subParts.join(" ｜ ")) + "</span>" : "") +
            "</td>" +
            '<td><span class="a-mono">' + (m.code_hint ? esc(m.code_hint) : '<span class="a-tag disabled">未生成</span>') + "</span></td>" +
            "<td>" + statusTag(m.status) + "</td>" +
            '<td><span class="a-mono">' + esc(fmt(m.created_at)) + "</span></td>" +
            '<td><span class="a-mono">' + esc(m.last_login_at ? fmt(m.last_login_at) : "从未登录") + "</span></td>" +
            '<td><div class="a-actions">' + actions + "</div></td></tr>";
        })
        .join("");
    }

    var pager = $("#member-pager");
    if (pager) {
      var totalPages = Math.max(1, Math.ceil(data.total / data.page_size));
      pager.innerHTML =
        '<button type="button" data-page-to="' + (data.page - 1) + '"' + (data.page <= 1 ? " disabled" : "") + ">上一页</button>" +
        "<span>第 " + data.page + " / " + totalPages + " 页 · 共 " + data.total + " 名会员</span>" +
        '<button type="button" data-page-to="' + (data.page + 1) + '"' + (data.page >= totalPages ? " disabled" : "") + ">下一页</button>";
      $$("[data-page-to]", pager).forEach(function (btn) {
        btn.addEventListener("click", function () {
          memberState.page = parseInt(btn.getAttribute("data-page-to"), 10);
          loadMembers();
        });
      });
    }

    $$("#member-rows [data-act]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        handleMemberAction(btn.getAttribute("data-act"), parseInt(btn.getAttribute("data-id"), 10), btn);
      });
    });
  }

  async function loadMembers() {
    var params = new URLSearchParams();
    if (memberState.q) params.set("q", memberState.q);
    if (memberState.status) params.set("status", memberState.status);
    params.set("page", String(memberState.page));
    params.set("page_size", String(memberState.pageSize));

    try {
      var data = await api("/api/admin/members?" + params.toString());
      renderMembers(data);
    } catch (err) {
      toast(err.message, true);
    }
  }

  function askConfirm(message) {
    return window.confirm(message);
  }

  async function handleMemberAction(action, id, button) {
    var messages = {
      rotate: "重新生成后，旧访问码立即失效。确认要重置吗？",
      pause: "暂停后该会员的已有登录会立即失效，确认暂停？",
      disable: "停用后该会员无法再进入会员中心，确认停用？",
      resume: "确认恢复该会员的访问权限？",
      revoke: "确认让该会员的所有登录会话立即失效？",
      delete: "删除为软删除，会员将无法登录。确认删除？",
    };
    if (!askConfirm(messages[action] || "确认执行该操作？")) return;

    button.disabled = true;
    try {
      if (action === "rotate") {
        var rotated = await api("/api/admin/members/" + id + "/rotate-code", { method: "POST" });
        toast("访问码已重置");
        showCodeDialog(rotated.access_code, "会员编号 " + rotated.member_code + " · 旧访问码已失效");
        loadMembers();
        return;
      }
      if (action === "delete") {
        var del = await api("/api/admin/members/" + id, { method: "DELETE" });
        toast("会员已删除");
        loadMembers();
        return;
      }
      if (action === "revoke") {
        await api("/api/admin/members/" + id + "/revoke-sessions", { method: "POST" });
        toast("该会员的所有会话已失效");
        return;
      }
      var statusMap = { pause: "paused", disable: "disabled", resume: "active" };
      await api("/api/admin/members/" + id + "/status", { method: "POST", body: { status: statusMap[action] } });
      toast("会员状态已更新");
      loadMembers();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  }

  function showCodeDialog(code, meta) {
    var dialog = $("#code-dialog");
    if (!dialog) return;
    $("#code-value").textContent = code;
    $("#code-meta").textContent = meta || "";
    dialog.showModal();
  }

  function initMembers() {
    bindDialogBasics();

    var dialog = $("#member-dialog");
    var form = $("#member-form");
    var alertEl = $("#member-alert");
    var submit = $("#member-submit");

    $$("[data-open-member]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        form.reset();
        hideAlert(alertEl);
        submit.disabled = false;
        dialog.showModal();
      });
    });

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      hideAlert(alertEl);
      submit.disabled = true;
      var fd = new FormData(form);
      try {
        var created = await api("/api/admin/members", {
          method: "POST",
          body: {
            name: fd.get("name"),
            contact: fd.get("contact"),
            wechat_note: fd.get("wechat_note"),
            source: fd.get("source"),
            notes: fd.get("notes"),
          },
        });
        dialog.close();
        showCodeDialog(created.access_code, "会员编号 " + created.member.member_code + " · VIP会员");
        loadMembers();
      } catch (err) {
        showAlert(alertEl, err.message);
        submit.disabled = false;
      }
    });

    var copyBtn = $("#code-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var value = $("#code-value").textContent || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(value).then(function () {
            toast("访问码已复制");
          }, function () {
            toast("复制失败，请手动选择文本复制", true);
          });
        } else {
          toast("请手动选择访问码复制");
        }
      });
    }

    $("#member-search-btn").addEventListener("click", function () {
      memberState.q = String($("#member-search").value || "").trim();
      memberState.status = String($("#member-status").value || "");
      memberState.page = 1;
      loadMembers();
    });
    $("#member-search").addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        $("#member-search-btn").click();
      }
    });
    $("#member-status").addEventListener("change", function () {
      $("#member-search-btn").click();
    });

    loadMembers();
  }

  /* ---------------- 分类选项 ---------------- */

  var categoriesPromise = null;
  function loadCategories() {
    if (!categoriesPromise) {
      categoriesPromise = api("/api/admin/categories")
        .then(function (data) {
          return data.items || [];
        })
        .catch(function (err) {
          categoriesPromise = null;
          throw err;
        });
    }
    return categoriesPromise;
  }

  function fillCategorySelect(select, items, placeholder) {
    if (!select) return;
    var groups = { course: "课程分类", resource: "资料分类" };
    var html = '<option value="">' + esc(placeholder || "未分类") + "</option>";
    ["course", "resource"].forEach(function (type) {
      var list = items.filter(function (c) {
        return c.type === type;
      });
      if (!list.length) return;
      html += '<optgroup label="' + groups[type] + '">';
      list.forEach(function (c) {
        html += '<option value="' + c.id + '">' + esc(c.name) + "</option>";
      });
      html += "</optgroup>";
    });
    select.innerHTML = html;
  }

  /* ---------------- 课程管理 ---------------- */

  var contentState = { q: "", status: "" };
  var contentEditingId = null;
  var contentAttachment = null;
  var contentFormat = "markdown"; // markdown | html
  var contentChapters = []; // [{title, body, sort_order}]

  function syncAttachment(attachment) {
    contentAttachment = attachment || null;
    var hint = $("#content-attach-hint");
    var removeBtn = $("#content-attach-remove");
    if (!hint || !removeBtn) return;

    if (!contentEditingId) {
      hint.textContent = "先保存课程，再上传附件（≤200 MB）。";
      removeBtn.hidden = true;
      return;
    }
    if (contentAttachment) {
      hint.textContent = "当前附件：" + contentAttachment.file_name;
      removeBtn.hidden = false;
    } else {
      hint.textContent = "尚未上传附件，≤200 MB，存 R2 私有存储，仅授权用户可下载。";
      removeBtn.hidden = true;
    }
  }

  function contentRowHtml(c) {
    var actions =
      '<button class="a-mini" data-act="edit" data-id="' + c.id + '">编辑</button>' +
      (c.status === "published"
        ? '<button class="a-mini" data-act="archive" data-id="' + c.id + '">下架</button>'
        : '<button class="a-mini" data-act="publish" data-id="' + c.id + '">发布</button>') +
      '<button class="a-mini danger" data-act="delete" data-id="' + c.id + '" data-name="' + esc(c.title) + '">删除</button>';

    return "<tr><td><span class=\"a-cell-title\">" + esc(c.title) + '</span><span class="a-cell-sub mono">' +
      esc(c.slug) + " · " + (c.body_length || 0) + " 字符" +
      (c.attachment_name ? " · 附件 " + esc(c.attachment_name) : "") + "</span></td>" +
      "<td>" + esc(c.category_name || "未分类") + "</td>" +
      "<td>" + accessTag(c.access_level) + "</td>" +
      "<td>" + statusTag(c.status) + "</td>" +
      '<td><span class="a-mono">' + esc(c.sort_order) + "</span></td>" +
      '<td><span class="a-mono">' + esc(fmt(c.updated_at)) + "</span></td>" +
      '<td><div class="a-actions">' + actions + "</div></td></tr>";
  }

  function renderContents(items) {
    var rows = $("#content-rows");
    if (!rows) return;

    if (!items.length) {
      rows.innerHTML = '<tr><td colspan="7" class="a-empty">还没有课程内容，先写一篇吧。</td></tr>';
      bindContentRowActions();
      return;
    }

    var grouped = $("#content-group-toggle") && $("#content-group-toggle").checked;
    if (grouped) {
      var groups = {};
      items.forEach(function (c) {
        var key = c.category_name || "未分类";
        if (!groups[key]) groups[key] = [];
        groups[key].push(c);
      });
      var keys = Object.keys(groups).sort();
      var html = "";
      keys.forEach(function (k) {
        html += '<tr class="a-group-row"><td colspan="7"><strong>' + esc(k) + "</strong> <span class=\"a-hint\">(" + groups[k].length + ")</span></td></tr>";
        html += groups[k].map(contentRowHtml).join("");
      });
      rows.innerHTML = html;
    } else {
      rows.innerHTML = items.map(contentRowHtml).join("");
    }

    bindContentRowActions();
  }

  function bindContentRowActions() {
    $$("#content-rows [data-act]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = parseInt(btn.getAttribute("data-id"), 10);
        var act = btn.getAttribute("data-act");
        if (act === "edit") {
          openContentEditor(id);
          return;
        }
        if (act === "delete") {
          deleteContent(id, btn.getAttribute("data-name") || "", btn);
          return;
        }
        setContentStatus(id, act === "publish" ? "published" : "archived", btn);
      });
    });
  }

  async function deleteContent(id, name, button) {
    if (!askConfirm("确认删除课程「" + name + "」吗？\n\n删除后前台与会员中心都不再显示该课程，操作会记录到安全日志。此操作不可撤销。")) {
      return;
    }
    button.disabled = true;
    try {
      await api("/api/admin/contents/" + id + "/delete", { method: "POST" });
      toast("课程已删除");
      loadContents();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  }

  async function loadContents() {
    var params = new URLSearchParams();
    if (contentState.q) params.set("q", contentState.q);
    if (contentState.status) params.set("status", contentState.status);
    try {
      var data = await api("/api/admin/contents?" + params.toString());
      renderContents(data.items || []);
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function setContentStatus(id, status, button) {
    button.disabled = true;
    try {
      await api("/api/admin/contents/" + id + "/status", { method: "POST", body: { status: status } });
      toast(status === "published" ? "内容已发布" : "内容已下架");
      loadContents();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  }

  function openContentEditor(id) {
    var dialog = $("#content-dialog");
    var form = $("#content-form");
    var alertEl = $("#content-alert");
    var submit = $("#content-submit");
    if (!dialog || !form) return;
    hideAlert(alertEl);
    // 复位保存按钮状态：上一次保存成功后对话框关闭，按钮可能仍处于 disabled
    if (submit) {
      submit.disabled = false;
      submit.textContent = "保存";
    }

    Promise.all([loadCategories(), id ? api("/api/admin/contents/" + id) : Promise.resolve(null)])
      .then(function (result) {
        var items = result[0];
        var data = result[1];
        fillCategorySelect(form.elements.category_id, items, "未分类");

        if (data) {
          contentEditingId = data.item.id;
          $("#content-dialog-title").textContent = "编辑课程";
          form.elements.title.value = data.item.title || "";
          form.elements.slug.value = data.item.slug || "";
          form.elements.category_id.value = data.item.category_id || "";
          form.elements.nav_category.value = data.item.nav_category || "";
          form.elements.cover_image.value = data.item.cover_image || "";
          form.elements.content_type.value = data.item.content_type || "article";
          form.elements.access_level.value = data.item.access_level || "member";
          form.elements.status.value = data.item.status || "draft";
          form.elements.sort_order.value = data.item.sort_order || 0;
          form.elements.excerpt.value = data.item.excerpt || "";
          contentFormat = data.item.content_format === "html" ? "html" : "markdown";
          contentChapters = (data.item.chapters || []).map(function (c) {
            return { title: c.title, body: c.body, sort_order: c.sort_order };
          });
          setContentFormat(contentFormat, data.item.body || "");
          $("#content-meta").textContent =
            "创建 " + fmt(data.item.created_at) + " · 更新 " + fmt(data.item.updated_at);
          syncAttachment(data.item.attachment);
        } else {
          contentEditingId = null;
          $("#content-dialog-title").textContent = "新建课程";
          form.reset();
          form.elements.access_level.value = "member";
          form.elements.status.value = "draft";
          form.elements.sort_order.value = 0;
          form.elements.nav_category.value = "";
          form.elements.cover_image.value = "";
          contentFormat = "markdown";
          contentChapters = [];
          setContentFormat("markdown", "");
          $("#content-meta").textContent = "正文支持 Markdown 或富文本，保存草稿不会出现在会员中心。";
          syncAttachment(null);
        }
        applyContentTypeUI();
        renderChapters();
        dialog.showModal();
      })
      .catch(function (err) {
        toast(err.message, true);
      });
  }

  // 设置正文格式（markdown/html），并把已有正文灌入对应编辑器
  function setContentFormat(format, body) {
    contentFormat = format;
    var seg = $("#content-format-seg");
    if (seg) {
      seg.querySelectorAll(".a-seg-btn").forEach(function (b) {
        b.classList.toggle("is-active", b.getAttribute("data-format") === format);
      });
    }
    $("#content-body-markdown").hidden = format !== "markdown";
    $("#content-body-html").hidden = format !== "html";
    $("#content-rt-toolbar-wrap").hidden = format !== "html";
    var ta = document.querySelector("#content-form textarea[name='body']");
    var rt = $("#content-rt");
    if (format === "markdown") {
      if (ta) ta.value = body || "";
    } else {
      if (rt) rt.innerHTML = body || "";
      if (ta) ta.value = "";
    }
  }

  // 根据内容类型显示正文区或章景区
  function applyContentTypeUI() {
    var form = $("#content-form");
    if (!form) return;
    var type = form.elements.content_type.value;
    var isChapter = type === "chapter";
    $("#content-body-markdown").hidden = isChapter || contentFormat !== "markdown";
    $("#content-body-html").hidden = isChapter || contentFormat !== "html";
    $("#content-rt-toolbar-wrap").hidden = contentFormat !== "html";
    $("#content-chapters").hidden = !isChapter;
  }

  // 渲染章节目录
  function renderChapters() {
    var list = $("#chapter-list");
    if (!list) return;
    if (!contentChapters.length) {
      list.innerHTML = '<p class="a-hint">还没有章节，点击「添加章节」开始。</p>';
      return;
    }
    var isHtml = contentFormat === "html";
    list.innerHTML = contentChapters
      .map(function (ch, i) {
        var bodyField = isHtml
          ? '<div class="a-chapter-rt" contenteditable="true" data-idx="' + i + '">' + (ch.body || "") + "</div>"
          : '<textarea class="a-chapter-body" data-idx="' + i + '" rows="6" placeholder="章节正文（Markdown）…">' + esc(ch.body || "") + "</textarea>";
        return '<div class="a-chapter-item">' +
          '<div class="a-chapter-head">' +
            '<span class="a-mono">第 ' + (i + 1) + " 章</span>" +
            '<input type="text" placeholder="章节标题" data-ch-title data-idx="' + i + '" value="' + esc(ch.title || "") + '">' +
            '<button type="button" class="a-mini" data-ch-up data-idx="' + i + '">↑</button>' +
            '<button type="button" class="a-mini" data-ch-down data-idx="' + i + '">↓</button>' +
            '<button type="button" class="a-mini danger" data-ch-del data-idx="' + i + '">删</button>' +
          "</div>" +
          bodyField +
          "</div>";
      })
      .join("");

    list.querySelectorAll("[data-ch-title]").forEach(function (el) {
      el.addEventListener("input", function () {
        var i = +el.getAttribute("data-idx");
        if (contentChapters[i]) contentChapters[i].title = el.value;
      });
    });
    list.querySelectorAll("textarea.a-chapter-body").forEach(function (el) {
      el.addEventListener("input", function () {
        var i = +el.getAttribute("data-idx");
        if (contentChapters[i]) contentChapters[i].body = el.value;
      });
    });
    list.querySelectorAll("div.a-chapter-rt").forEach(function (el) {
      el.addEventListener("input", function () {
        var i = +el.getAttribute("data-idx");
        if (contentChapters[i]) contentChapters[i].body = el.innerHTML;
      });
    });
    list.querySelectorAll("[data-ch-up]").forEach(function (b) {
      b.addEventListener("click", function () {
        var i = +b.getAttribute("data-idx");
        if (i > 0) {
          var tmp = contentChapters[i];
          contentChapters[i] = contentChapters[i - 1];
          contentChapters[i - 1] = tmp;
          renderChapters();
        }
      });
    });
    list.querySelectorAll("[data-ch-down]").forEach(function (b) {
      b.addEventListener("click", function () {
        var i = +b.getAttribute("data-idx");
        if (i < contentChapters.length - 1) {
          var tmp = contentChapters[i];
          contentChapters[i] = contentChapters[i + 1];
          contentChapters[i + 1] = tmp;
          renderChapters();
        }
      });
    });
    list.querySelectorAll("[data-ch-del]").forEach(function (b) {
      b.addEventListener("click", function () {
        var i = +b.getAttribute("data-idx");
        if (window.confirm("删除第 " + (i + 1) + " 章？")) {
          contentChapters.splice(i, 1);
          renderChapters();
        }
      });
    });
  }

  // 从编辑器采集正文
  function collectContentBody() {
    if (contentFormat === "html") {
      var rt = $("#content-rt");
      return rt ? rt.innerHTML : "";
    }
    var ta = document.querySelector("#content-form textarea[name='body']");
    return ta ? ta.value : "";
  }

  function initContent() {
    bindDialogBasics();

    var dialog = $("#content-dialog");
    var form = $("#content-form");
    var alertEl = $("#content-alert");
    var submit = $("#content-submit");

    $$("[data-new-content]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        openContentEditor(null);
      });
    });

    // 正文格式切换
    $$("#content-format-seg .a-seg-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        var fmt = b.getAttribute("data-format");
        var current = collectContentBody();
        setContentFormat(fmt, current);
        applyContentTypeUI();
        renderChapters();
      });
    });

    // 内容类型切换
    var contentTypeSelect = form.elements.content_type;
    if (contentTypeSelect) {
      contentTypeSelect.addEventListener("change", applyContentTypeUI);
    }

    // 添加章节
    var addChapterBtn = $("#chapter-add");
    if (addChapterBtn) {
      addChapterBtn.addEventListener("click", function () {
        contentChapters.push({ title: "", body: "", sort_order: contentChapters.length });
        renderChapters();
      });
    }

    // 富文本工具栏：对当前聚焦的 contenteditable 执行命令
    var rtToolbar = $("#content-rt-toolbar");
    if (rtToolbar) {
      rtToolbar.addEventListener("mousedown", function (e) {
        e.preventDefault(); // 防止失焦
      });
      rtToolbar.addEventListener("click", function (e) {
        var btn = e.target.closest("button[data-cmd]");
        if (!btn) return;
        var cmd = btn.getAttribute("data-cmd");
        var val = btn.getAttribute("data-val") || null;
        if (cmd === "createLink") {
          var url = window.prompt("输入链接地址（http/https）：", "https://");
          if (url) document.execCommand("createLink", false, url);
        } else if (val) {
          document.execCommand(cmd, false, val);
        } else {
          document.execCommand(cmd, false, null);
        }
      });
    }

    var imageBtn = $("#content-image-upload");
    if (imageBtn) {
      imageBtn.addEventListener("click", async function () {
        var input = $("#content-image");
        var hint = $("#content-image-hint");
        var file = input && input.files && input.files[0];
        if (!file) {
          showAlert(alertEl, "请选择要上传的图片。");
          return;
        }

        imageBtn.disabled = true;
        imageBtn.textContent = "上传中…";
        hideAlert(alertEl);
        try {
          var fd = new FormData();
          fd.append("file", file);
          var res = await fetch("/api/admin/uploads/image", {
            method: "POST",
            credentials: "same-origin",
            body: fd,
          });
          var data = await res.json().catch(function () {
            return null;
          });
          if (res.status === 401) {
            location.href = "/admin/";
            return;
          }
          if (!res.ok || !data || !data.ok) {
            throw new Error((data && data.message) || "图片上传失败，请稍后重试。");
          }

          if (contentFormat === "html") {
            // 富文本模式：在当前聚焦的 contenteditable 光标处插入图片
            var target = document.activeElement;
            if (target && target.isContentEditable) {
              target.focus();
              document.execCommand("insertImage", false, data.url);
            } else {
              var rt = $("#content-rt");
              if (rt) {
                rt.focus();
                document.execCommand("insertImage", false, data.url);
              }
            }
          } else {
            var ta = form.elements.body;
            var insert = "\n\n![图片说明](" + data.url + ")\n\n";
            var start = typeof ta.selectionStart === "number" ? ta.selectionStart : ta.value.length;
            var end = typeof ta.selectionEnd === "number" ? ta.selectionEnd : ta.value.length;
            ta.value = ta.value.slice(0, start) + insert + ta.value.slice(end);
            ta.focus();
          }
          if (hint) hint.textContent = "已插入： " + data.url;
          toast("图片已上传并插入正文");
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          imageBtn.disabled = false;
          imageBtn.textContent = "上传并插入";
        }
      });
    }

    var attachBtn = $("#content-attach-upload");
    if (attachBtn) {
      attachBtn.addEventListener("click", async function () {
        if (!contentEditingId) {
          showAlert(alertEl, "请先保存课程，再上传附件。");
          return;
        }
        var input = $("#content-attach");
        var file = input && input.files && input.files[0];
        if (!file) {
          showAlert(alertEl, "请选择要上传的附件。");
          return;
        }

        attachBtn.disabled = true;
        attachBtn.textContent = "上传中…";
        hideAlert(alertEl);
        try {
          var fd = new FormData();
          fd.append("file", file);
          var res = await fetch("/api/admin/contents/" + contentEditingId + "/attachment", {
            method: "POST",
            credentials: "same-origin",
            body: fd,
          });
          var data = await res.json().catch(function () {
            return null;
          });
          if (res.status === 401) {
            location.href = "/admin/";
            return;
          }
          if (!res.ok || !data || !data.ok) {
            throw new Error((data && data.message) || "附件上传失败，请稍后重试。");
          }
          syncAttachment(data.item);
          toast("附件已上传");
          loadContents();
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          attachBtn.disabled = false;
          attachBtn.textContent = "上传附件";
        }
      });
    }

    var attachRemoveBtn = $("#content-attach-remove");
    if (attachRemoveBtn) {
      attachRemoveBtn.addEventListener("click", async function () {
        if (!contentEditingId || !contentAttachment) return;
        if (!window.confirm("删除后会员将无法下载该附件，确认删除？")) return;

        attachRemoveBtn.disabled = true;
        hideAlert(alertEl);
        try {
          await api("/api/admin/contents/" + contentEditingId + "/attachment/remove", { method: "POST" });
          syncAttachment(null);
          toast("附件已删除");
          loadContents();
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          attachRemoveBtn.disabled = false;
        }
      });
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      if (submit.disabled) return; // 防重复提交
      hideAlert(alertEl);
      submit.disabled = true;
      var originalText = submit.textContent || "保存";
      submit.textContent = "保存中…";

      var fd = new FormData(form);
      var contentType = fd.get("content_type");
      var payload = {
        title: fd.get("title"),
        slug: fd.get("slug"),
        category_id: fd.get("category_id") || null,
        nav_category: fd.get("nav_category") || null,
        cover_image: fd.get("cover_image") || "",
        content_type: contentType,
        content_format: contentFormat,
        access_level: fd.get("access_level"),
        status: fd.get("status"),
        sort_order: fd.get("sort_order"),
        excerpt: fd.get("excerpt"),
        body: contentType === "chapter" ? "" : collectContentBody(),
        chapters: contentType === "chapter"
          ? contentChapters.map(function (c, i) {
              return { title: c.title, body: c.body, sort_order: i };
            })
          : [],
      };

      try {
        if (contentEditingId) {
          await api("/api/admin/contents/" + contentEditingId, { method: "POST", body: payload });
          toast("课程已保存");
        } else {
          await api("/api/admin/contents", { method: "POST", body: payload });
          toast("课程已创建");
        }
        dialog.close();
        loadContents();
      } catch (err) {
        showAlert(alertEl, err.message);
      } finally {
        submit.disabled = false;
        submit.textContent = originalText;
      }
    });

    $("#content-search-btn").addEventListener("click", function () {
      contentState.q = String($("#content-search").value || "").trim();
      contentState.status = String($("#content-status").value || "");
      loadContents();
    });
    $("#content-search").addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        $("#content-search-btn").click();
      }
    });
    $("#content-status").addEventListener("change", function () {
      $("#content-search-btn").click();
    });

    // 按分类分组切换
    var groupToggle = $("#content-group-toggle");
    if (groupToggle) {
      groupToggle.addEventListener("change", function () {
        loadContents();
      });
    }

    // 课程分类管理
    initCategoryManagement(loadContents);

    loadContents();
  }

  function initCategoryManagement(onChange) {
    var rowsEl = $("#category-rows");
    if (!rowsEl) return;
    var itemsCache = [];

    function renderCategories(items) {
      itemsCache = items || [];
      if (!itemsCache.length) {
        rowsEl.innerHTML = '<tr><td colspan="6" class="a-empty">暂无分类，添加一个开始。</td></tr>';
        return;
      }
      var typeLabel = { course: "课程", resource: "资料", tool: "工具" };
      rowsEl.innerHTML = itemsCache.map(function (c) {
        return '<tr>' +
          '<td>' + esc(c.name) + '</td>' +
          '<td class="a-mono">' + esc(c.slug) + '</td>' +
          '<td>' + (typeLabel[c.type] || c.type) + '</td>' +
          '<td>' + (c.status === "disabled" ? '<span class="m-tag">已禁用</span>' : '<span class="m-tag free">启用</span>') + '</td>' +
          '<td class="a-mono">' + esc(c.sort_order) + '</td>' +
          '<td class="a-right"><div class="a-actions">' +
            '<button class="a-mini" data-cat-edit="' + c.id + '">编辑</button>' +
            '<button class="a-mini danger" data-cat-del="' + c.id + '" data-name="' + esc(c.name) + '">删除</button>' +
          '</div></td>' +
        '</tr>';
      }).join("");

      rowsEl.querySelectorAll("[data-cat-edit]").forEach(function (b) {
        b.addEventListener("click", function () { editCategory(+b.getAttribute("data-cat-edit")); });
      });
      rowsEl.querySelectorAll("[data-cat-del]").forEach(function (b) {
        b.addEventListener("click", function () { deleteCategory(+b.getAttribute("data-cat-del"), b.getAttribute("data-name")); });
      });
    }

    async function loadCategories() {
      try {
        var data = await api("/api/admin/categories");
        renderCategories(data.items || []);
      } catch (err) {
        rowsEl.innerHTML = '<tr><td colspan="6" class="a-empty">' + esc(err.message) + "</td></tr>";
      }
    }

    async function createCategory() {
      var name = ($("#cat-name").value || "").trim();
      var slug = ($("#cat-slug").value || "").trim().toLowerCase();
      if (!name || !slug) { toast("请填写分类名称和标识", true); return; }
      try {
        await api("/api/admin/categories", {
          method: "POST",
          body: {
            name: name, slug: slug,
            type: $("#cat-type").value,
            sort_order: Number($("#cat-sort").value || 0),
            status: $("#cat-status").value,
          },
        });
        $("#cat-name").value = "";
        $("#cat-slug").value = "";
        toast("分类已添加");
        loadCategories();
        if (onChange) onChange();
      } catch (err) { toast(err.message, true); }
    }

    function editCategory(id) {
      var c = itemsCache.filter(function (x) { return x.id === id; })[0];
      if (!c) return;
      var name = window.prompt("分类名称：", c.name);
      if (name === null) return;
      var slug = window.prompt("标识 slug：", c.slug);
      if (slug === null) return;
      api("/api/admin/categories/" + id, {
        method: "POST",
        body: { name: name.trim(), slug: slug.trim().toLowerCase(), type: c.type, sort_order: c.sort_order, status: c.status },
      })
        .then(function () { toast("分类已更新"); loadCategories(); if (onChange) onChange(); })
        .catch(function (err) { toast(err.message, true); });
    }

    function deleteCategory(id, name) {
      api("/api/admin/categories/" + id, { method: "DELETE" })
        .then(function () { toast("分类已删除"); loadCategories(); if (onChange) onChange(); })
        .catch(async function (err) {
          // 409：分类仍有关联课程，询问是否迁移后删除
          if (err.code === "category_in_use") {
            var target = window.prompt(
              "该分类仍有关联课程，无法直接删除。\n输入目标分类 ID 进行迁移后删除（留空则设为未分类）：",
              ""
            );
            if (target === null) return;
            var targetId = target.trim() === "" ? null : Number(target.trim());
            if (target !== "" && !Number.isFinite(targetId)) { toast("目标分类 ID 无效", true); return; }
            try {
              await api("/api/admin/categories/" + id + "/migrate", {
                method: "POST",
                body: { target_category_id: targetId },
              });
              toast("已迁移并删除分类");
              loadCategories();
              if (onChange) onChange();
            } catch (e) { toast(e.message, true); }
          } else {
            toast(err.message, true);
          }
        });
    }

    var createBtn = $("#cat-create");
    if (createBtn) createBtn.addEventListener("click", createCategory);

    loadCategories();
  }

  /* ---------------- 资料管理 ---------------- */

  var resourceEditingId = null;

  function renderResources(items) {
    var rows = $("#resource-rows");
    if (!rows) return;

    if (!items.length) {
      rows.innerHTML = '<tr><td colspan="7" class="a-empty">还没有资料，先添加一份。</td></tr>';
      return;
    }

    rows.innerHTML = items
      .map(function (r) {
        var actions =
          '<button class="a-mini" data-act="edit" data-id="' + r.id + '">编辑</button>' +
          (r.status === "published"
            ? '<button class="a-mini" data-act="archive" data-id="' + r.id + '">下架</button>'
            : '<button class="a-mini" data-act="publish" data-id="' + r.id + '">发布</button>') +
          '<button class="a-mini danger" data-act="delete" data-id="' + r.id + '" data-name="' + esc(r.title) + '">删除</button>';

        return "<tr><td><span class=\"a-cell-title\">" + esc(r.title) + '</span><span class="a-cell-sub">' +
          esc(r.description || "") + "</span></td>" +
          "<td>" + esc(r.category_name || "未分类") + "</td>" +
          '<td><span class="a-mono">' + esc(r.file_type || "file") + " · " +
          esc(r.file_name || r.file_key) + "</span>" +
          '<span class="a-cell-sub mono">' + esc(r.file_key) + "</span></td>" +
          "<td>" + accessTag(r.access_level) + "</td>" +
          "<td>" + statusTag(r.status) + "</td>" +
          '<td><span class="a-mono">' + esc(fmt(r.updated_at)) + "</span></td>" +
          '<td><div class="a-actions">' + actions + "</div></td></tr>";
      })
      .join("");

    $$("#resource-rows [data-act]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var id = parseInt(btn.getAttribute("data-id"), 10);
        var act = btn.getAttribute("data-act");
        if (act === "edit") {
          openResourceEditor(id);
          return;
        }
        if (act === "delete") {
          deleteResource(id, btn.getAttribute("data-name") || "", btn);
          return;
        }
        setResourceStatus(id, act === "publish" ? "published" : "archived", btn);
      });
    });
  }

  async function deleteResource(id, name, button) {
    if (!askConfirm("确认删除资料「" + name + "」吗？\n\n删除后会员中心不再显示该资料，R2 中的文件会保留以防误删共用文件，操作会记录到安全日志。此操作不可撤销。")) {
      return;
    }
    button.disabled = true;
    try {
      await api("/api/admin/resources/" + id + "/delete", { method: "POST" });
      toast("资料已删除");
      loadResources();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  }

  async function loadResources() {
    try {
      var data = await api("/api/admin/resources");
      renderResources(data.items || []);
    } catch (err) {
      toast(err.message, true);
    }
  }

  async function setResourceStatus(id, status, button) {
    button.disabled = true;
    try {
      await api("/api/admin/resources/" + id + "/status", { method: "POST", body: { status: status } });
      toast(status === "published" ? "资料已发布" : "资料已下架");
      loadResources();
    } catch (err) {
      toast(err.message, true);
      button.disabled = false;
    }
  }

  function openResourceEditor(id) {
    var dialog = $("#resource-dialog");
    var form = $("#resource-form");
    var alertEl = $("#resource-alert");
    if (!dialog || !form) return;
    hideAlert(alertEl);

    Promise.all([loadCategories(), id ? api("/api/admin/resources").then(function (data) {
      return (data.items || []).filter(function (r) { return r.id === id; })[0];
    }) : Promise.resolve(null)])
      .then(function (result) {
        var items = result[0];
        var item = result[1];
        fillCategorySelect(form.elements.category_id, items, "未分类");

        if (item) {
          resourceEditingId = item.id;
          $("#resource-dialog-title").textContent = "编辑资料";
          form.elements.title.value = item.title || "";
          form.elements.description.value = item.description || "";
          form.elements.file_key.value = item.file_key || "";
          form.elements.file_name.value = item.file_name || "";
          form.elements.file_type.value = item.file_type || "pdf";
          form.elements.file_size.value = item.file_size || 0;
          form.elements.version.value = item.version || "v1.0";
          form.elements.sort_order.value = item.sort_order || 0;
          form.elements.category_id.value = item.category_id || "";
          form.elements.access_level.value = item.access_level || "member";
          form.elements.status.value = item.status || "draft";
        } else {
          resourceEditingId = null;
          $("#resource-dialog-title").textContent = "添加资料";
          form.reset();
          form.elements.file_type.value = "pdf";
          form.elements.version.value = "v1.0";
          form.elements.access_level.value = "member";
          form.elements.status.value = "draft";
        }
        var uploadBox = $("#resource-upload-box");
        if (uploadBox) uploadBox.hidden = !item;
        dialog.showModal();
      })
      .catch(function (err) {
        toast(err.message, true);
      });
  }

  function initResources() {
    bindDialogBasics();

    var dialog = $("#resource-dialog");
    var form = $("#resource-form");
    var alertEl = $("#resource-alert");
    var submit = $("#resource-submit");

    $$("[data-new-resource]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        openResourceEditor(null);
      });
    });

    var uploadBtn = $("#resource-upload");
    if (uploadBtn) {
      uploadBtn.addEventListener("click", async function () {
        var fileInput = $("#resource-file");
        var hint = $("#resource-upload-hint");
        if (!resourceEditingId) {
          showAlert(alertEl, "请先保存资料，再上传文件。");
          return;
        }
        var file = fileInput && fileInput.files && fileInput.files[0];
        if (!file) {
          showAlert(alertEl, "请选择要上传的文件。");
          return;
        }

        uploadBtn.disabled = true;
        uploadBtn.textContent = "上传中…";
        hideAlert(alertEl);
        try {
          var fd = new FormData();
          fd.append("file", file);
          var res = await fetch("/api/admin/resources/" + resourceEditingId + "/file", {
            method: "POST",
            credentials: "same-origin",
            body: fd,
          });
          var data = await res.json().catch(function () {
            return null;
          });
          if (res.status === 401) {
            location.href = "/admin/";
            return;
          }
          if (!res.ok || !data || !data.ok) {
            throw new Error((data && data.message) || "上传失败，请稍后重试。");
          }
          form.elements.file_key.value = data.item.file_key;
          form.elements.file_name.value = data.item.file_name;
          form.elements.file_type.value = data.item.file_type;
          form.elements.file_size.value = data.item.file_size;
          if (hint) hint.textContent = "已上传：" + data.item.file_name + "（" + Math.max(1, Math.round(data.item.file_size / 1024)) + " KB）";
          toast("文件已上传到 R2 私有存储");
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          uploadBtn.disabled = false;
          uploadBtn.textContent = "上传并保存";
        }
      });
    }

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      hideAlert(alertEl);
      submit.disabled = true;
      var fd = new FormData(form);
      var payload = {
        title: fd.get("title"),
        description: fd.get("description"),
        file_key: fd.get("file_key"),
        file_name: fd.get("file_name"),
        file_type: fd.get("file_type"),
        file_size: fd.get("file_size"),
        version: fd.get("version"),
        sort_order: fd.get("sort_order"),
        category_id: fd.get("category_id") || null,
        access_level: fd.get("access_level"),
        status: fd.get("status"),
      };

      try {
        if (resourceEditingId) {
          await api("/api/admin/resources/" + resourceEditingId, { method: "POST", body: payload });
          toast("资料已保存");
        } else {
          await api("/api/admin/resources", { method: "POST", body: payload });
          toast("资料已添加");
        }
        dialog.close();
        loadResources();
      } catch (err) {
        showAlert(alertEl, err.message);
        submit.disabled = false;
      }
    });

    loadResources();
  }

  /* ---------------- 安全日志 ---------------- */

  async function initAudit() {
    var rows = $("#audit-rows");
    async function load() {
      try {
        var data = await api("/api/admin/audit?limit=150");
        var items = data.items || [];
        if (!items.length) {
          rows.innerHTML = '<tr><td colspan="5" class="a-empty">暂无日志。</td></tr>';
          return;
        }
        rows.innerHTML = items
          .map(function (row) {
            return "<tr><td><span class=\"a-mono\">" + esc(fmt(row.created_at)) + "</span></td>" +
              "<td>" + esc(row.actor_type) + (row.actor_id ? " #" + esc(row.actor_id) : "") + "</td>" +
              "<td><span class=\"a-mono\">" + esc(row.action) + "</span></td>" +
              "<td>" + esc(row.detail || "—") + "</td>" +
              '<td><span class="a-mono">' + esc(row.ip_hash || "—") + "</span></td></tr>";
          })
          .join("");
      } catch (err) {
        toast(err.message, true);
      }
    }

    var refresh = $("#audit-refresh");
    if (refresh) refresh.addEventListener("click", load);
    load();
  }

  async function initTools() {
    var rows = $("#tool-rows");
    var dialog = $("#tool-dialog");
    var form = $("#tool-form");
    var alertEl = $("#tool-alert");
    var editingId = null;
    var cache = [];

    function render(items) {
      cache = items;
      if (!items.length) {
        rows.innerHTML = '<tr><td colspan="6" class="a-empty">暂无工具。</td></tr>';
        return;
      }
      rows.innerHTML = items
        .map(function (t) {
          var actions =
            '<button class="a-link" type="button" data-act="edit" data-id="' + t.id + '">编辑</button>';
          actions +=
            t.status === "published"
              ? '<button class="a-link danger" type="button" data-act="archive" data-id="' + t.id + '">下架</button>'
              : '<button class="a-link" type="button" data-act="publish" data-id="' + t.id + '">发布</button>';
          actions +=
            '<button class="a-link danger" type="button" data-act="delete" data-id="' + t.id + '" data-name="' + esc(t.name) + '">删除</button>';
          return "<tr><td><span class=\"a-cell-title\">" + esc(t.name) + '</span><span class="a-cell-sub mono">' +
            esc(t.slug) + "</span></td>" +
            '<td><span class="a-mono">' + esc(t.entry_url) + "</span></td>" +
            "<td>" + accessTag(t.access_level) + "</td>" +
            "<td>" + statusTag(t.status) + "</td>" +
            '<td><span class="a-mono">' + esc(fmt(t.updated_at)) + "</span></td>" +
            '<td><div class="a-actions">' + actions + "</div></td></tr>";
        })
        .join("");

      $$("#tool-rows [data-act]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var id = parseInt(btn.getAttribute("data-id"), 10);
          var act = btn.getAttribute("data-act");
          if (act === "edit") {
            openEditor(id);
            return;
          }
          if (act === "delete") {
            deleteTool(id, btn.getAttribute("data-name") || "", btn);
            return;
          }
          setStatus(id, act === "publish" ? "published" : "archived", btn);
        });
      });
    }

    async function deleteTool(id, name, button) {
      if (!askConfirm("确认删除工具「" + name + "」吗？\n\n删除后会员中心不再显示该工具，操作会记录到安全日志。此操作不可撤销。")) {
        return;
      }
      button.disabled = true;
      try {
        await api("/api/admin/tools/" + id + "/delete", { method: "POST" });
        toast("工具已删除");
        load();
      } catch (err) {
        toast(err.message, true);
        button.disabled = false;
      }
    }

    async function load() {
      try {
        var data = await api("/api/admin/tools");
        render(data.items || []);
      } catch (err) {
        toast(err.message, true);
      }
    }

    function openEditor(id) {
      if (!dialog || !form) return;
      hideAlert(alertEl);
      var item = cache.filter(function (t) {
        return t.id === id;
      })[0];

      if (item) {
        editingId = item.id;
        $("#tool-dialog-title").textContent = "编辑工具";
        form.elements.name.value = item.name || "";
        form.elements.slug.value = item.slug || "";
        form.elements.entry_url.value = item.entry_url || "";
        form.elements.intro.value = item.intro || "";
        form.elements.usage_text.value = item.usage_text || "";
        form.elements.access_level.value = item.access_level || "member";
        form.elements.status.value = item.status || "draft";
        form.elements.sort_order.value = item.sort_order || 0;
      } else {
        editingId = null;
        $("#tool-dialog-title").textContent = "添加工具";
        form.reset();
        form.elements.access_level.value = "member";
        form.elements.status.value = "draft";
      }
      dialog.showModal();
    }

    async function setStatus(id, status, button) {
      button.disabled = true;
      try {
        await api("/api/admin/tools/" + id + "/status", { method: "POST", body: { status: status } });
        toast(status === "published" ? "工具已发布" : "工具已下架");
        load();
      } catch (err) {
        toast(err.message, true);
        button.disabled = false;
      }
    }

    $$("[data-new-tool]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        openEditor(null);
      });
    });

    if (form) {
      form.addEventListener("submit", async function (event) {
        event.preventDefault();
        hideAlert(alertEl);
        var submit = $("#tool-submit");
        submit.disabled = true;
        try {
          var payload = {
            name: form.elements.name.value,
            slug: form.elements.slug.value,
            entry_url: form.elements.entry_url.value,
            intro: form.elements.intro.value,
            usage_text: form.elements.usage_text.value,
            access_level: form.elements.access_level.value,
            status: form.elements.status.value,
            sort_order: Number(form.elements.sort_order.value || 0),
          };
          if (editingId) {
            await api("/api/admin/tools/" + editingId, { method: "POST", body: payload });
            toast("工具已更新");
          } else {
            await api("/api/admin/tools", { method: "POST", body: payload });
            toast("工具已创建");
          }
          dialog.close();
          load();
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          submit.disabled = false;
        }
      });
    }

    load();
  }

  /* ---------------- 案例管理 ---------------- */

  function initCases() {
    var rows = $("#case-rows");
    var dialog = $("#case-dialog");
    var form = $("#case-form");
    var alertEl = $("#case-alert");
    var editingId = null;
    var cache = [];
    var state = { q: "", status: "" };
    var caseFormat = "markdown";

    function render(items) {
      cache = items;
      if (!items.length) {
        rows.innerHTML = '<tr><td colspan="7" class="a-empty">还没有案例，先新建一个。</td></tr>';
        return;
      }
      rows.innerHTML = items
        .map(function (c) {
          var actions =
            '<button class="a-mini" data-act="edit" data-id="' + c.id + '">编辑</button>' +
            (c.status === "published"
              ? '<button class="a-mini" data-act="archive" data-id="' + c.id + '">下架</button>'
              : '<button class="a-mini" data-act="publish" data-id="' + c.id + '">发布</button>') +
            '<button class="a-mini danger" data-act="delete" data-id="' + c.id + '" data-name="' + esc(c.title) + '">删除</button>';

          return "<tr><td><span class=\"a-cell-title\">" + esc(c.title) + '</span><span class="a-cell-sub mono">' +
            esc(c.slug) + "</span></td>" +
            "<td>" + esc(c.category || "未分类") + "</td>" +
            "<td>" + statusTag(c.status) + "</td>" +
            "<td>" + (c.show_on_home ? '<span class="a-tag free">首页</span>' : "—") + "</td>" +
            '<td><span class="a-mono">' + esc(c.sort_order) + "</span></td>" +
            '<td><span class="a-mono">' + esc(fmt(c.updated_at)) + "</span></td>" +
            '<td><div class="a-actions">' + actions + "</div></td></tr>";
        })
        .join("");

      $$("#case-rows [data-act]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          var id = parseInt(btn.getAttribute("data-id"), 10);
          var act = btn.getAttribute("data-act");
          if (act === "edit") {
            openEditor(id);
            return;
          }
          if (act === "delete") {
            deleteCase(id, btn.getAttribute("data-name") || "", btn);
            return;
          }
          setStatus(id, act === "publish" ? "published" : "archived", btn);
        });
      });
    }

    async function load() {
      var params = new URLSearchParams();
      if (state.q) params.set("q", state.q);
      if (state.status) params.set("status", state.status);
      try {
        var data = await api("/api/admin/cases?" + params.toString());
        render(data.items || []);
      } catch (err) {
        toast(err.message, true);
      }
    }

    function toLocalInput(iso) {
      if (!iso) return "";
      var d = new Date(iso);
      if (!Number.isFinite(d.getTime())) return "";
      var pad = function (n) { return String(n).padStart(2, "0"); };
      return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) +
        "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
    }

    function setCaseFormat(format, body) {
      caseFormat = format;
      var seg = $("#case-format-seg");
      if (seg) {
        seg.querySelectorAll(".a-seg-btn").forEach(function (b) {
          b.classList.toggle("is-active", b.getAttribute("data-format") === format);
        });
      }
      $("#case-body-markdown").hidden = format !== "markdown";
      $("#case-body-html").hidden = format !== "html";
      var ta = document.querySelector("#case-form textarea[name='body']");
      var rt = $("#case-rt");
      if (format === "markdown") {
        if (ta) ta.value = body || "";
      } else {
        if (rt) rt.innerHTML = body || "";
        if (ta) ta.value = "";
      }
    }
    function collectCaseBody() {
      if (caseFormat === "html") {
        var rt = $("#case-rt");
        return rt ? rt.innerHTML : "";
      }
      var ta = document.querySelector("#case-form textarea[name='body']");
      return ta ? ta.value : "";
    }

    function openEditor(id) {
      if (!dialog || !form) return;
      hideAlert(alertEl);
      var caseSubmit = $("#case-submit");
      if (caseSubmit) {
        caseSubmit.disabled = false;
        caseSubmit.textContent = "保存";
      }

      function populate(item) {
        if (item) {
          editingId = item.id;
          $("#case-dialog-title").textContent = "编辑案例";
          form.elements.title.value = item.title || "";
          form.elements.slug.value = item.slug || "";
          form.elements.category.value = item.category || "";
          form.elements.status.value = item.status || "draft";
          form.elements.sort_order.value = item.sort_order || 0;
          form.elements.show_on_home.value = item.show_on_home ? "1" : "0";
          form.elements.published_at.value = toLocalInput(item.published_at);
          form.elements.external_link.value = item.external_link || "";
          form.elements.summary.value = item.summary || "";
          form.elements.cover_image.value = item.cover_image || "";
          caseFormat = item.content_format === "html" ? "html" : "markdown";
          setCaseFormat(caseFormat, item.body || "");
          $("#case-meta").textContent = "创建 " + fmt(item.created_at) + " · 更新 " + fmt(item.updated_at);
        } else {
          editingId = null;
          $("#case-dialog-title").textContent = "新建案例";
          form.reset();
          form.elements.status.value = "draft";
          form.elements.sort_order.value = 0;
          form.elements.show_on_home.value = "0";
          caseFormat = "markdown";
          setCaseFormat("markdown", "");
          $("#case-meta").textContent = "发布后前台 /cases/ 立即可见；勾选首页展示才会出现在首页板块。";
        }
        dialog.showModal();
      }

      if (id) {
        // 列表接口不返回正文，编辑时必须拉取完整记录，避免空正文覆盖原内容
        api("/api/admin/cases/" + id)
          .then(function (data) {
            populate(data.item);
          })
          .catch(function (err) {
            toast(err.message, true);
          });
        return;
      }
      populate(null);
    }

    async function setStatus(id, status, button) {
      button.disabled = true;
      try {
        await api("/api/admin/cases/" + id + "/status", { method: "POST", body: { status: status } });
        toast(status === "published" ? "案例已发布" : "案例已下架");
        load();
      } catch (err) {
        toast(err.message, true);
        button.disabled = false;
      }
    }

    async function deleteCase(id, name, button) {
      if (!askConfirm("确认删除案例「" + name + "」吗？\n\n删除后首页与 /cases/ 都不再显示该案例，操作会记录到安全日志。此操作不可撤销。")) {
        return;
      }
      button.disabled = true;
      try {
        await api("/api/admin/cases/" + id + "/delete", { method: "POST" });
        toast("案例已删除");
        load();
      } catch (err) {
        toast(err.message, true);
        button.disabled = false;
      }
    }

    $$("[data-new-case]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        openEditor(null);
      });
    });

    var searchInput = $("#case-search");
    var searchBtn = $("#case-search-btn");
    var statusSelect = $("#case-status");
    if (searchBtn) {
      searchBtn.addEventListener("click", function () {
        state.q = searchInput ? searchInput.value.trim() : "";
        state.status = statusSelect ? statusSelect.value : "";
        load();
      });
    }
    if (searchInput) {
      searchInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
          event.preventDefault();
          state.q = searchInput.value.trim();
          state.status = statusSelect ? statusSelect.value : "";
          load();
        }
      });
    }

    var coverBtn = $("#case-cover-upload");
    if (coverBtn) {
      coverBtn.addEventListener("click", async function () {
        var input = $("#case-cover");
        var hint = $("#case-cover-hint");
        var file = input && input.files && input.files[0];
        if (!file) {
          showAlert(alertEl, "请选择要上传的封面图片。");
          return;
        }
        coverBtn.disabled = true;
        coverBtn.textContent = "上传中…";
        hideAlert(alertEl);
        try {
          var fd = new FormData();
          fd.append("file", file);
          var res = await fetch("/api/admin/uploads/image", {
            method: "POST",
            credentials: "same-origin",
            body: fd,
          });
          var data = await res.json().catch(function () { return null; });
          if (res.status === 401) {
            location.href = "/admin/";
            return;
          }
          if (!res.ok || !data || !data.ok) {
            throw new Error((data && data.message) || "封面上传失败，请稍后重试。");
          }
          form.elements.cover_image.value = data.url;
          if (hint) hint.textContent = "已上传：" + data.url;
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          coverBtn.disabled = false;
          coverBtn.textContent = "上传封面";
        }
      });
    }

    // 案例正文格式切换
    $$("#case-format-seg .a-seg-btn").forEach(function (b) {
      b.addEventListener("click", function () {
        var fmt = b.getAttribute("data-format");
        var current = collectCaseBody();
        setCaseFormat(fmt, current);
      });
    });

    // 案例富文本工具栏
    var caseToolbar = $("#case-rt-toolbar");
    if (caseToolbar) {
      caseToolbar.addEventListener("mousedown", function (e) { e.preventDefault(); });
      caseToolbar.addEventListener("click", function (e) {
        var btn = e.target.closest("button[data-cmd]");
        if (!btn) return;
        var cmd = btn.getAttribute("data-cmd");
        var val = btn.getAttribute("data-val") || null;
        if (cmd === "createLink") {
          var url = window.prompt("输入链接地址（http/https）：", "https://");
          if (url) document.execCommand("createLink", false, url);
        } else if (val) {
          document.execCommand(cmd, false, val);
        } else {
          document.execCommand(cmd, false, null);
        }
      });
    }

    // 案例正文配图上传并插入
    var caseBodyImgBtn = $("#case-body-image-upload");
    if (caseBodyImgBtn) {
      caseBodyImgBtn.addEventListener("click", async function () {
        var input = $("#case-body-image");
        var hint = $("#case-body-image-hint");
        var file = input && input.files && input.files[0];
        if (!file) {
          showAlert(alertEl, "请选择要上传的图片。");
          return;
        }
        caseBodyImgBtn.disabled = true;
        caseBodyImgBtn.textContent = "上传中…";
        hideAlert(alertEl);
        try {
          var fd = new FormData();
          fd.append("file", file);
          var res = await fetch("/api/admin/uploads/image", {
            method: "POST",
            credentials: "same-origin",
            body: fd,
          });
          var data = await res.json().catch(function () { return null; });
          if (res.status === 401) { location.href = "/admin/"; return; }
          if (!res.ok || !data || !data.ok) {
            throw new Error((data && data.message) || "图片上传失败，请稍后重试。");
          }
          if (caseFormat === "html") {
            var rt = $("#case-rt");
            if (rt) { rt.focus(); document.execCommand("insertImage", false, data.url); }
          } else {
            var ta = form.elements.body;
            var insert = "\n\n![图片说明](" + data.url + ")\n\n";
            var start = typeof ta.selectionStart === "number" ? ta.selectionStart : ta.value.length;
            var end = typeof ta.selectionEnd === "number" ? ta.selectionEnd : ta.value.length;
            ta.value = ta.value.slice(0, start) + insert + ta.value.slice(end);
            ta.focus();
          }
          if (hint) hint.textContent = "已插入：" + data.url;
          toast("图片已上传并插入正文");
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          caseBodyImgBtn.disabled = false;
          caseBodyImgBtn.textContent = "上传并插入";
        }
      });
    }

    if (form) {
      form.addEventListener("submit", async function (event) {
        event.preventDefault();
        var submit = $("#case-submit");
        if (submit && submit.disabled) return; // 防重复提交
        hideAlert(alertEl);
        if (submit) {
          submit.disabled = true;
          var originText = submit.textContent || "保存";
          submit.textContent = "保存中…";
        }
        try {
          var publishedRaw = form.elements.published_at.value;
          var payload = {
            title: form.elements.title.value,
            slug: form.elements.slug.value,
            category: form.elements.category.value,
            status: form.elements.status.value,
            sort_order: Number(form.elements.sort_order.value || 0),
            show_on_home: form.elements.show_on_home.value === "1" ? 1 : 0,
            published_at: publishedRaw ? new Date(publishedRaw).toISOString() : "",
            external_link: form.elements.external_link.value,
            summary: form.elements.summary.value,
            cover_image: form.elements.cover_image.value,
            content_format: caseFormat,
            body: collectCaseBody(),
          };
          if (editingId) {
            await api("/api/admin/cases/" + editingId, { method: "POST", body: payload });
            toast("案例已更新");
          } else {
            await api("/api/admin/cases", { method: "POST", body: payload });
            toast("案例已创建");
          }
          dialog.close();
          load();
        } catch (err) {
          showAlert(alertEl, err.message);
        } finally {
          if (submit) {
            submit.disabled = false;
            submit.textContent = originText || "保存";
          }
        }
      });
    }

    load();
  }

  /* ---------------- 网站设置 ---------------- */

  function initSettings() {
    var form = $("#settings-form");
    if (!form) return;

    var alertEl = $("#settings-alert");
    var submit = $("#settings-submit");

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      hideAlert(alertEl);
      submit.disabled = true;

      var payload = {
        brand_name: form.elements.brand_name.value,
        tagline: form.elements.tagline.value,
        intro: form.elements.intro.value,
        wechat: form.elements.wechat.value,
        footer_text: form.elements.footer_text.value,
      };

      try {
        await api("/api/admin/settings", { method: "POST", body: payload });
        showAlert(alertEl, "设置已保存，约 1 分钟后所有页面生效。", true);
        toast("网站设置已保存");
      } catch (err) {
        showAlert(alertEl, err.message);
      } finally {
        submit.disabled = false;
      }
    });

    /* ---------------- 页面文案与导航配置 ---------------- */
    var copyForm = $("#copy-form");
    if (copyForm) {
      var copyAlert = $("#copy-alert");
      var copySubmit = $("#copy-submit");
      var copyReset = $("#copy-reset");
      var copyDefaults = {};
      try {
        copyDefaults = JSON.parse(copyForm.getAttribute("data-defaults") || "{}");
      } catch (e) {
        copyDefaults = {};
      }

      function collectCopy() {
        var payload = {};
        $$("input[name], textarea[name]", copyForm).forEach(function (el) {
          if (el.name && el.name.indexOf(".") > 0) payload[el.name] = el.value;
        });
        return payload;
      }

      copyForm.addEventListener("submit", async function (event) {
        event.preventDefault();
        hideAlert(copyAlert);
        copySubmit.disabled = true;
        try {
          await api("/api/admin/copy", { method: "POST", body: collectCopy() });
          showAlert(copyAlert, "文案已保存，刷新页面即可看到最新效果。", true);
          toast("文案配置已保存");
        } catch (err) {
          showAlert(copyAlert, err.message);
        } finally {
          copySubmit.disabled = false;
        }
      });

      copyReset.addEventListener("click", function () {
        if (!window.confirm("确定要将全部页面文案恢复为默认值吗？此操作不可撤销。")) return;
        hideAlert(copyAlert);
        copyReset.disabled = true;
        api("/api/admin/copy/reset", { method: "POST" })
          .then(function () {
            $$("input[name], textarea[name]", copyForm).forEach(function (el) {
              el.value = copyDefaults[el.name] || "";
            });
            showAlert(copyAlert, "已恢复为默认文案，刷新页面生效。", true);
            toast("文案已恢复默认");
          })
          .catch(function (err) {
            showAlert(copyAlert, err.message);
          })
          .finally(function () {
            copyReset.disabled = false;
          });
      });
    }
  }

  /* ---------------- 入口 ---------------- */

  if (page === "login" || page === "setup") {
    initAuth();
    return;
  }

  bindDialogBasics();

  if (page === "overview") initOverview();
  else if (page === "members") initMembers();
  else if (page === "content") initContent();
  else if (page === "resources") initResources();
  else if (page === "tools") initTools();
  else if (page === "cases") initCases();
  else if (page === "settings") initSettings();
  else if (page === "audit") initAudit();
})();
