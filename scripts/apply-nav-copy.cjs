// 批量为公开静态页面的导航项包裹 data-copy span（不改变 URL 与功能）
const fs = require("fs");
const path = require("path");

const files = [
  "build/index.html",
  "build/shopify-day-one.html",
  "guide/index.html",
  "guide/90-day-roadmap.html",
  "marketing/index.html",
  "marketing/first-ad.html",
  "products/index.html",
  "products/validation.html",
];

// 主导航（无 small）
const headerNav = [
  ['href="/">首页</a>', 'href="/"><span data-copy="public.nav.home">首页</span></a>'],
  ['href="/courses/">免费课程</a>', 'href="/courses/"><span data-copy="public.nav.courses">免费课程</span></a>'],
  ['href="/guide/">独立站入门</a>', 'href="/guide/"><span data-copy="public.nav.guide">独立站入门</span></a>'],
  ['href="/products/">选品知识库</a>', 'href="/products/"><span data-copy="public.nav.products">选品知识库</span></a>'],
  ['href="/build/">建站教程</a>', 'href="/build/"><span data-copy="public.nav.build">建站教程</span></a>'],
  ['href="/marketing/">营销知识</a>', 'href="/marketing/"><span data-copy="public.nav.marketing">营销知识</span></a>'],
  ['href="/cases/">学员案例</a>', 'href="/cases/"><span data-copy="public.nav.cases">学员案例</span></a>'],
];

// 移动端导航（带 small）
const mobileNav = [
  ['href="/">首页 <small>01</small></a>', 'href="/"><span data-copy="public.nav.home">首页</span> <small>01</small></a>'],
  ['href="/courses/">免费课程 <small>02</small></a>', 'href="/courses/"><span data-copy="public.nav.courses">免费课程</span> <small>02</small></a>'],
  ['href="/guide/">独立站入门 <small>03</small></a>', 'href="/guide/"><span data-copy="public.nav.guide">独立站入门</span> <small>03</small></a>'],
  ['href="/products/">选品知识库 <small>04</small></a>', 'href="/products/"><span data-copy="public.nav.products">选品知识库</span> <small>04</small></a>'],
  ['href="/build/">建站教程 <small>05</small></a>', 'href="/build/"><span data-copy="public.nav.build">建站教程</span> <small>05</small></a>'],
  ['href="/marketing/">营销知识 <small>06</small></a>', 'href="/marketing/"><span data-copy="public.nav.marketing">营销知识</span> <small>06</small></a>'],
  ['href="/cases/">学员案例 <small>07</small></a>', 'href="/cases/"><span data-copy="public.nav.cases">学员案例</span> <small>07</small></a>'],
];

const ctaHeader = ['header-cta" href="/member/">会员中心</a>', 'header-cta" href="/member/"><span data-copy="public.nav.member">会员中心</span></a>'];
const ctaMobile = ['btn-block" href="/member/">进入会员中心</a>', 'btn-block" href="/member/"><span data-copy="public.nav.member">会员中心</span></a>'];

// 页脚导航链接
const footerNav = [
  ['href="/guide/">独立站入门</a>', 'href="/guide/"><span data-copy="public.nav.guide">独立站入门</span></a>'],
  ['href="/products/">选品知识库</a>', 'href="/products/"><span data-copy="public.nav.products">选品知识库</span></a>'],
  ['href="/build/">建站教程</a>', 'href="/build/"><span data-copy="public.nav.build">建站教程</span></a>'],
  ['href="/marketing/">营销知识</a>', 'href="/marketing/"><span data-copy="public.nav.marketing">营销知识</span></a>'],
  ['href="/member/">会员中心</a>', 'href="/member/"><span data-copy="public.nav.member">会员中心</span></a>'],
  ['href="/cases/">学员案例</a>', 'href="/cases/"><span data-copy="public.nav.cases">学员案例</span></a>'],
];

const all = [...headerNav, ...mobileNav, ctaHeader, ctaMobile, ...footerNav];

let totalChanged = 0;
for (const rel of files) {
  const fp = path.join(__dirname, "..", "public", rel);
  if (!fs.existsSync(fp)) {
    console.log("skip (not found):", rel);
    continue;
  }
  let html = fs.readFileSync(fp, "utf8");
  let changed = 0;
  for (const [from, to] of all) {
    if (html.includes(from)) {
      html = html.split(from).join(to);
      changed++;
    }
  }
  if (changed) {
    fs.writeFileSync(fp, html, "utf8");
    console.log(`updated ${rel} (${changed} replacements)`);
    totalChanged++;
  } else {
    console.log(`no change: ${rel}`);
  }
}
console.log(`done, ${totalChanged} files modified`);
