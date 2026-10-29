// Copy buttons, tabs, the story stage, scroll reveals, and the nav. The page
// works without this file: every panel's content is already in the HTML.
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

for (const btn of document.querySelectorAll('.copy')) {
  btn.addEventListener('click', async () => {
    const text = btn.closest('[data-copy]').dataset.copy;
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = 'Copied';
      btn.classList.add('done');
    } catch {
      btn.textContent = 'Select and copy';
    }
    setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('done'); }, 1600);
  });
}

// Fit each terminal capture to its window: the largest font up to 14px whose
// widest line fits, measured, because browsers round monospace advances.
const fit = (pre) => {
  pre.style.fontSize = '';
  const room = pre.clientWidth;
  if (!room || pre.scrollWidth <= room) return;
  let lo = 8.5;
  let hi = parseFloat(getComputedStyle(pre).fontSize);
  for (let i = 0; i < 10; i++) {
    const mid = (lo + hi) / 2;
    pre.style.fontSize = mid + 'px';
    if (pre.scrollWidth <= room) lo = mid; else hi = mid;
  }
  pre.style.fontSize = lo + 'px';
};
const terms = document.querySelectorAll('pre.term:not(.http)');
const sized = new ResizeObserver((entries) => {
  for (const e of entries) fit(e.target.querySelector('pre.term'));
});
document.fonts.ready.then(() => {
  for (const pre of terms) {
    fit(pre);
    sized.observe(pre.closest('.win'));
  }
});

// Tabs with arrow-key navigation (WAI-ARIA tabs pattern). show(tab) selects a
// tab; panels are found through aria-controls.
function tablist(list, onShow) {
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  const show = (tab, focus) => {
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute('aria-controls')).hidden = !on;
    }
    if (focus) tab.focus();
    if (onShow) onShow(tab);
  };
  list.addEventListener('click', (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (tab) show(tab);
  });
  list.addEventListener('keydown', (e) => {
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const next = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (next) {
      e.preventDefault();
      show(tabs[(i + next + tabs.length) % tabs.length], true);
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      show(tabs[e.key === 'Home' ? 0 : tabs.length - 1], true);
    }
  });
}
for (const list of document.querySelectorAll('[role="tablist"]')) tablist(list);

// Story: on wide screens, move each step's visual into the sticky stage and
// show the one whose step is in the middle of the viewport.
const story = document.querySelector('.story');
if (story) {
  const stage = story.querySelector('.stage');
  const steps = [...story.querySelectorAll('.step')];
  const visuals = steps.map((s) => s.querySelector('.step-visual'));
  const wide = matchMedia('(min-width: 1041px)');
  let active = null;
  const activate = (i) => {
    if (active === i) return;
    active = i;
    steps.forEach((s, j) => s.classList.toggle('active', j === i));
    visuals.forEach((v, j) => v.classList.toggle('show', j === i));
  };
  const layout = () => {
    if (wide.matches) {
      for (const v of visuals) stage.append(v);
      story.classList.add('staged');
      active = null;
      activate(0);
    } else {
      steps.forEach((s, i) => s.append(visuals[i]));
      story.classList.remove('staged');
      visuals.forEach((v) => v.classList.remove('show'));
    }
  };
  layout();
  wide.addEventListener('change', layout);
  const io = new IntersectionObserver((entries) => {
    if (!story.classList.contains('staged')) return;
    for (const e of entries) if (e.isIntersecting) activate(steps.indexOf(e.target));
  }, { rootMargin: '-45% 0px -45% 0px' });
  for (const s of steps) io.observe(s);
}

// Reveal blocks as they scroll in.
const reveals = document.querySelectorAll('.reveal');
if (reduced || !('IntersectionObserver' in window)) {
  for (const el of reveals) el.classList.add('in');
} else {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) {
        e.target.classList.add('in');
        io.unobserve(e.target);
      }
    }
  }, { rootMargin: '0px 0px -8% 0px' });
  for (const el of reveals) io.observe(el);
}

// Nav: a border once the page scrolls, and the current section in bold.
const nav = document.querySelector('.nav');
const onScroll = () => nav.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true });
onScroll();
const links = new Map([...document.querySelectorAll('.links a')].map((a) => [a.hash.slice(1), a]));
const spy = new IntersectionObserver((entries) => {
  for (const e of entries) {
    const a = links.get(e.target.id);
    if (a) a.classList.toggle('current', e.isIntersecting);
  }
}, { rootMargin: '-50% 0px -50% 0px' });
for (const id of links.keys()) {
  const el = document.getElementById(id);
  if (el) spy.observe(el);
}
