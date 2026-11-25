import { render } from 'preact';
import '@/ui/style.css';
import { Options } from '@/ui/Options';

const root = document.getElementById('app');
if (root) render(<Options />, root);
