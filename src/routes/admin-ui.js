const express = require('express');
const router = express.Router();
const { requireAuth, requireAdmin } = require('../middleware/auth');
const users = require('../db/users');

// Simple admin UI page
router.get('/admin-ui', requireAuth, requireAdmin, async (req, res) => {
  const allUsers = await users.listAll();
  res.send(`
    <html>
      <head>
        <title>Admin User Management</title>
        <style>
          body { font-family: sans-serif; margin: 2em; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ccc; padding: 0.5em; }
          th { background: #eee; }
          button { margin: 0 0.2em; }
        </style>
      </head>
      <body>
        <h1>Admin User Management</h1>
        <table>
          <thead>
            <tr><th>ID</th><th>Email</th><th>Role</th><th>Email Verified</th><th>Permissions</th><th>Actions</th></tr>
          </thead>
          <tbody>
            ${allUsers.map(u => `
              <tr>
                <td>${u.id}</td>
                <td>${u.email}</td>
                <td>${u.role}</td>
                <td>${u.email_verified ? '✔️' : ''}</td>
                <td><input id="perm-${u.id}" value="${u.permissions || ''}" style="width:140px" /></td>
                <td>
                  <button onclick="changeRole(${u.id}, '${u.role === 'admin' ? 'user' : 'admin'}')">${u.role === 'admin' ? 'Demote' : 'Promote'} to ${u.role === 'admin' ? 'User' : 'Admin'}</button>
                  <button onclick="savePerm(${u.id})">Save Perms</button>
                  <button onclick="deleteUser(${u.id})">Delete</button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        <script>
          async function changeRole(id, role) {
            const res = await fetch('/auth/admin/users/' + id + '/role', {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json', 'Authorization': localStorage.token ? 'Bearer ' + localStorage.token : '' },
              body: JSON.stringify({ role })
            });
            if (res.ok) location.reload();
            else alert('Failed to change role');
          }
          async function savePerm(id) {
            const permissions = document.getElementById('perm-' + id).value;
            const res = await fetch('/auth/admin/users/' + id + '/permissions', {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json', 'Authorization': localStorage.token ? 'Bearer ' + localStorage.token : '' },
              body: JSON.stringify({ permissions })
            });
            if (res.ok) location.reload();
            else alert('Failed to update permissions');
          }
          async function deleteUser(id) {
            if (!confirm('Delete user?')) return;
            const res = await fetch('/auth/admin/users/' + id, {
              method: 'DELETE',
              headers: { 'Authorization': localStorage.token ? 'Bearer ' + localStorage.token : '' }
            });
            if (res.ok) location.reload();
            else alert('Failed to delete user');
          }
        </script>
      </body>
    </html>
  `);
});

module.exports = router;
