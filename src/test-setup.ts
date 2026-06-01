import '@testing-library/jest-dom/vitest'

const reactActEnvironment = globalThis as typeof globalThis & {
	IS_REACT_ACT_ENVIRONMENT?: boolean
	self?: typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
	window?: typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }
}

reactActEnvironment.IS_REACT_ACT_ENVIRONMENT = true

if (reactActEnvironment.self) {
	reactActEnvironment.self.IS_REACT_ACT_ENVIRONMENT = true
}

if (reactActEnvironment.window) {
	reactActEnvironment.window.IS_REACT_ACT_ENVIRONMENT = true
}
