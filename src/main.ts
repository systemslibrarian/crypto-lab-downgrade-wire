import './styles.css';
import { mount } from './ui/dom';
import {
  failOpenPanel,
  historicalPanel,
  introPanel,
  policyPanel,
  scopePanel,
  sentinelPanel,
  stripPanel,
} from './ui/panels';

const app = document.getElementById('app');
if (!app) throw new Error('missing #app mount point');

const main = document.createElement('main');
main.className = 'lab-main';
mount(
  main,
  introPanel(),
  stripPanel(),
  policyPanel(),
  sentinelPanel(),
  failOpenPanel(),
  historicalPanel(),
  scopePanel(),
);
app.append(main);
