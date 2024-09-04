import { NextFunction, Request, Response } from 'express';

declare global {
  namespace Express {
    export interface Request {
      suspiciousData: {
        headerSuspiciousWords: string[];
        bodySuspiciousWords: string[];
      };
    }
  }
}

const suspiciousWords = ['attack', 'malicious', 'drop table'];

const checkForSuspiciousWords = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const headers = JSON.stringify(req.headers);
  const body = JSON.stringify(req.body);

  let found = false;
  let headerSuspiciousWords: string[] = [];
  let bodySuspiciousWords: string[] = [];
  suspiciousWords.forEach((word) => {
    if (headers.includes(word) || body.includes(word)) {
      found = true;
    }
    if (headers.includes(word)) {
      headerSuspiciousWords.push(word);
    }
    if (body.includes(word)) {
      bodySuspiciousWords.push(word);
    }
  });

  if (found) {
    const alertMessage = `Suspicious activity detected. Headers: ${headers}, Body: ${body}`;
    console.log(alertMessage);
    req.suspiciousData = {
      headerSuspiciousWords,
      bodySuspiciousWords,
    };
  }

  next();
};

export default checkForSuspiciousWords;
