# typescript_tutorial_for_beginners_video

Link to [video](https://www.youtube.com/watch?v=d56mG7DezGs)

- A programming language built on top of typescript
- every valid JavaScript file is a valid typescript file
- Statically typed language (C++, C#, Java) `int number = 10;`
- JavaScript is dynamically-typed (e.g. `let number = 10; number = "a";` is valid JS)
- TypeScript is JavaScript with type-checking (e.g. `let x: number = 10; x = "a";` is invalid TypeScript).
- TypeScript is more than type-checking. It can provide code completion, refactoring, and other new features.
- TypeScript also has compilation. Browsers don't know typescript. This is called transpilation (.ts --> Compiler --> .js)


## index.ts

typescript

```ts
console.log('hello world');
let age: number = 20; 
// Bash: `tsc index.ts`
```

bash

``` bash
tsc index.ts
```

```js

output javascript:

"use strict";
console.log('hello world');
let age = 20;
// Bash: `tsc index.ts`
```

## tsc --init

creates `tsconfig.json`

## tsconfig.json

- rootDir is inferred (if not set) to longest common path  of all non-declaration input files.
- if you have a root `./index.ts` then files in `src/*.ts` you will get `dist/index.js` and `dist/src/*.ts`
- I can run `tsc` in my project and it will auto transpile
- `"target": "esnext"` or `"ES2016"` for supporting most browsers.

- tsc | "sourceMap": true | that will create `index.d.ts` and `index.d.ts.map` and `index.js` and `index.js.map`
- index.js.map is the source map. how are our map maps to our ts code. It's good for debuggers.

## built-in types

```ts
let sales: number = 1000
let course: string = 'TypeScript';
let number1: number = 123_456_789;
let number2 = 123; // automatically turns into a `number` (inferred)
```

## Stack

- Zustand --> Client-side state management. It's state that only lives locally in the app.
