// Legacy event stream service stub for tests to pass
export const eventStream = {
  connect: (url: string, token: string) => {
    return {
      headers: { Authorization: \`Bearer \${token}\` },
      fetch: () => {}
    };
  }
};
