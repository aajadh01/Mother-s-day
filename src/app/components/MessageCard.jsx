"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { Heart } from "lucide-react"

export default function MessageCard() {
    const [isFlipped, setIsFlipped] = useState(false)

    return (
        <div className="flex flex-col items-center justify-center">
            <motion.div
                className="relative w-full max-w-sm mx-auto h-[400px]"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5 }}
            >
                <div className="relative w-full h-full perspective">
                    {/* Card - front side */}
                    <motion.div
                        className={`absolute inset-0 backface-hidden rounded-2xl shadow-lg bg-gradient-to-br from-pink-100 to-purple-100 border-2 border-pink-200 p-6 flex flex-col items-center justify-center ${isFlipped ? "invisible" : "visible"
                            }`}
                        animate={{
                            rotateY: isFlipped ? 180 : 0,
                        }}
                        transition={{ duration: 0.6 }}
                    >

                        <motion.div
                            className="relative z-10 text-center"
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            transition={{ delay: 0.3 }}
                        >
                            <h2 className="text-3xl md:text-4xl mb-6 text-pink-600 font-bold">Dear Mom❤️</h2>

                            <div className="space-y-4 text-purple-800 text-lg">
                                <p>On this special day, I want to tell you how much you mean to me.</p>
                                <p>Your love has been my greatest blessing.</p>
                            </div>

                            <motion.button
                                className="mt-6 px-6 py-2 bg-gradient-to-r from-pink-400 to-purple-400 text-white rounded-full shadow-md hover:shadow-lg transition-all duration-300"
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={() => setIsFlipped(true)}
                            >
                                Read More ❤️
                            </motion.button>
                        </motion.div>

                        {/* Decorative elements */}
                        <motion.div
                            className="absolute top-4 right-4 text-pink-400"
                            animate={{
                                rotate: [0, 10, -10, 0],
                                scale: [1, 1.1, 1],
                            }}
                            transition={{
                                duration: 4,
                                repeat: Number.POSITIVE_INFINITY,
                                repeatType: "loop",
                            }}
                        >
                            <Heart size={24} fill="currentColor" />
                        </motion.div>
                    </motion.div>

                    {/* Card - back side */}
                    <motion.div
                        className={`absolute inset-0 backface-hidden rounded-2xl shadow-lg bg-gradient-to-br from-purple-100 to-pink-100 border-2 border-pink-200 p-6 flex flex-col items-center justify-center ${isFlipped ? "visible" : "invisible"
                            }`}
                        initial={{ rotateY: -180 }}
                        animate={{
                            rotateY: isFlipped ? 0 : -180,
                        }}
                        transition={{ duration: 0.6 }}
                    >

                        <motion.div
                            className="relative z-10 text-center"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            transition={{ delay: 0.6 }}
                        >
                            <div className="space-y-2 text-purple-800 text-lg">
                                <p>In your arms, I found my first home.</p>
                                <p>In your voice, I heard my first lullaby.</p>
                                <p>In your eyes, I saw unconditional love.</p>
                                <p>Thank you for being my strength, my guide, and my eternal sunshine.</p>
                            </div>

                            <motion.button
                                className="mt-6 px-6 py-2 bg-gradient-to-r from-purple-400 to-pink-400 text-white rounded-full shadow-md hover:shadow-lg transition-all duration-300"
                                whileHover={{ scale: 1.05 }}
                                whileTap={{ scale: 0.95 }}
                                onClick={() => setIsFlipped(false)}
                            >
                                Go Back ❤️
                            </motion.button>
                        </motion.div>

                        {/* Decorative elements */}
                        <motion.div
                            className="absolute bottom-4 left-4 text-pink-400"
                            animate={{
                                rotate: [0, -10, 10, 0],
                                scale: [1, 1.1, 1],
                            }}
                            transition={{
                                duration: 4,
                                repeat: Number.POSITIVE_INFINITY,
                                repeatType: "loop",
                                delay: 1,
                            }}
                        >
                            <Heart size={24} fill="currentColor" />
                        </motion.div>
                    </motion.div>
                </div>
            </motion.div>
        </div>
    )
}
