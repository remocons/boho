export async function resolve(specifier, context, nextResolve) {
  if (specifier === 'boho') return { url: new URL('../../dist/boho.js', import.meta.url).href, shortCircuit: true }
  return nextResolve(specifier, context)
}
