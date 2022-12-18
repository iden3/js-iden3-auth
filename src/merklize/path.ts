import { newFieldPathFromCtx, Path } from './internal/path';

export const getContextPathKey = async (
  docStr: string,
  ctxTyp: string,
  fieldPath: string,
): Promise<Path> => {
  return await newFieldPathFromCtx(docStr, ctxTyp, fieldPath);
};
