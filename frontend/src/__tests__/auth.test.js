import { describe, it, expect } from 'vitest'

describe('Authentication', () => {
  it('should validate email format', () => {
    const isValidEmail = (email) => /\S+@\S+\.\S+/.test(email)
    
    expect(isValidEmail('admin@medlinkpro.demo')).toBe(true)
    expect(isValidEmail('invalid-email')).toBe(false)
  })
  
  it('should validate password strength', () => {
    const isStrongPassword = (password) => password.length >= 8
    
    expect(isStrongPassword('Admin123!')).toBe(true)
    expect(isStrongPassword('weak')).toBe(false)
  })
})
