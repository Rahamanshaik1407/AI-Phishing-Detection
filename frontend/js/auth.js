// auth.js – wrapper around api for authentication UI actions
import * as api from './api.js';

export const auth = {
  async login(emailOrUsername, password) {
    const token = await api.login(emailOrUsername, password);
    sessionStorage.setItem('jwt', token);
    return token;
  },
  async register({ username, email, password }) {
    return api.register({ username, email, password });
  },
  logout() {
    sessionStorage.removeItem('jwt');
    window.location.href = 'login.html';
  },
  isAuthenticated() {
    return !!sessionStorage.getItem('jwt');
  }
};
