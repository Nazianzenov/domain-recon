import { render } from 'preact';
import '@/ui/style.css';
import { App } from '@/ui/App';

const root = document.getElementById('app');
if (root) render(<App />, root);
