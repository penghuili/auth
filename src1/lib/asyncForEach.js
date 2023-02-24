async function asyncForEach(arr, asyncFunc) {
  if (!arr || !arr.length) {
    return;
  }

  for (let index = 0; index < arr.length; index += 1) {
    // eslint-disable-next-line no-await-in-loop
    await asyncFunc(arr[index], index, arr);
  }
}

export default asyncForEach;
