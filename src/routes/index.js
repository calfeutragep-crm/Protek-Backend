const express = require('express');
const rateLimit = require('express-rate-limit');
const { register, login, me } = require('../controllers/auth.controller');
const {
  getUsers, getUser, approveUser, rejectUser, suspendUser, reactivateUser, updateUser,
  getRoles, getPermissions, getRolePermissions, updateRolePermissions,
  getNotifications, markNotificationRead, markAllNotificationsRead, getAuditLogs,
} = require('../controllers/users.controller');
const { requireAuth, requireOwner } = require('../middleware/auth');
const { getLeads, createLead, updateLead, getAppointments, updateAppointment, getAssignments, setAssignment } = require('../controllers/leads.controller');

const router = express.Router();

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10 });
const registerLimiter = rateLimit({ windowMs: 60*60*1000, max: 5 });

router.post('/auth/register', registerLimiter, register);
router.post('/auth/login', loginLimiter, login);
router.get('/auth/me', requireAuth, me);

router.get('/notifications', requireAuth, getNotifications);
router.patch('/notifications/:id/read', requireAuth, markNotificationRead);
router.patch('/notifications/read-all', requireAuth, markAllNotificationsRead);

router.get('/users', requireAuth, requireOwner, getUsers);
router.get('/users/:id', requireAuth, requireOwner, getUser);
router.patch('/users/:id', requireAuth, requireOwner, updateUser);
router.post('/users/:id/approve', requireAuth, requireOwner, approveUser);
router.post('/users/:id/reject', requireAuth, requireOwner, rejectUser);
router.post('/users/:id/suspend', requireAuth, requireOwner, suspendUser);
router.post('/users/:id/reactivate', requireAuth, requireOwner, reactivateUser);

router.get('/roles', requireAuth, getRoles);
router.get('/permissions', requireAuth, requireOwner, getPermissions);
router.get('/roles/:roleId/permissions', requireAuth, requireOwner, getRolePermissions);
router.put('/roles/:roleId/permissions', requireAuth, requireOwner, updateRolePermissions);

router.get('/audit-logs', requireAuth, requireOwner, getAuditLogs);

// Leads & Appointments
router.get('/leads', requireAuth, getLeads);
router.post('/leads', requireAuth, createLead);
router.patch('/leads/:id', requireAuth, updateLead);
router.get('/appointments', requireAuth, getAppointments);
router.patch('/appointments/:id', requireAuth, updateAppointment);

// Setter-closer assignments
router.get('/assignments', requireAuth, getAssignments);
router.put('/assignments', requireAuth, requireOwner, setAssignment);

module.exports = router;
