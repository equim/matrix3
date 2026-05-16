// A cache of chrome.storage.sync's `options` key, we want to check options in
// a lot of hot paths, and a storage.sync.get call everytime is suboptimal.
export default class Options {
    static #cache = null;
    static #promise;
    static #listeners = [];

    static #load() {
        Options.#promise ??= chrome.storage.sync.get("options").then(({ options }) => {
            Options.#cache = options || {};
            chrome.storage.onChanged.addListener((changes) => {
                if (!changes.options)
                    return;
                // Mutate in place so consumers can hold a stable reference.
                for (let key of Object.keys(Options.#cache))
                    delete Options.#cache[key];
                Object.assign(Options.#cache, changes.options.newValue ?? {});
                for (let callback of Options.#listeners)
                    callback(Options.#cache);
            });
        });
        return Options.#promise;
    }

    static async get() {
        if (Options.#cache === null)
            await Options.#load();
        return Options.#cache;
    }

    static addUpdateListener(callback) {
        Options.#listeners.push(callback);
    }
}
