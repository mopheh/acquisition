/* eslint-disable linebreak-style */
import logger from '#config/logger.js';
import { cookies } from '#utils/cookies.js';
import { jwttoken } from '#utils/jwt.js';

export const requireAuth = (req, res, next) => {
  try {
    const token = cookies.get(req, 'token');

    if (!token) {
      logger.warn('Authentication token missing');
      return res.status(401).json({ error: 'Authentication required' });
    }

    const payload = jwttoken.verify(token);

    req.user = {
      id: payload.id,
      email: payload.email,
      role: payload.role,
    };

    return next();
  } catch (error) {
    logger.error('Authentication middleware error', error);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

export const requireAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  return next();
};
