import Joi from 'joi';

export const trustSchema = Joi.object({
  email: Joi.string().optional(),
  phone: Joi.string().optional(),
  ip: Joi.string().optional(),
  wallet_address: Joi.string().optional(),
  wallet_chain: Joi.string().valid('ethereum', 'solana', 'bnb', 'xrp', 'auto').default('auto'),
  country_code: Joi.string().length(2).uppercase().optional(),
  use_case: Joi.string().valid('signup', 'login', 'checkout', 'kyc', 'airdrop', 'wallet_onboarding').default('signup'),
  content: Joi.string().max(10000).optional(),
  content_context: Joi.string().max(2000).optional(),
}).or('email', 'phone', 'ip', 'wallet_address', 'content').messages({
  'object.missing': 'At least one of email, phone, ip, wallet_address or content is required',
});