const mockHttpClient = {
  request: jest.fn(),
  post: jest.fn(),
  get: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
};

module.exports = mockHttpClient;
