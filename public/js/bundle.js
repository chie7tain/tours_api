/* eslint-disable */
/* eslint-disable */
import '@babel/polyfill';

import { login } from './login';
import { displayMap } from './leaflet';
// eslint-disable-next-line no-undef
const mapBox = document.getElementById('map');

if (mapBox) {
  const locations = JSON.parse(mapBox.dataset.locations);
  displayMap(locations);
}

document.querySelector('.form').addEventListener('submit', (e) => {
  e.preventDefault();

  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  login(email, password);
});
