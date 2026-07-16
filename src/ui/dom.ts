// Tiny hyperscript helper. Everything is built with createElement + setAttribute
// (never innerHTML with data), so nothing user-derived is ever parsed as markup.

type Child = Node | string | null | undefined | false;

export interface Props {
  class?: string;
  text?: string;
  html?: string; // static, author-controlled markup only
  attrs?: Record<string, string>;
  on?: Partial<Record<keyof HTMLElementEventMap, (ev: Event) => void>>;
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props.class) el.className = props.class;
  if (props.text !== undefined) el.textContent = props.text;
  if (props.html !== undefined) el.innerHTML = props.html;
  if (props.attrs) for (const [k, v] of Object.entries(props.attrs)) el.setAttribute(k, v);
  if (props.on) for (const [k, fn] of Object.entries(props.on)) el.addEventListener(k, fn as EventListener);
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return el;
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function panel(id: string, ...children: Child[]): HTMLElement {
  return h('section', { class: 'panel', attrs: { id } }, ...children);
}

export function mount(target: Element, ...nodes: Node[]): void {
  for (const n of nodes) target.append(n);
}
